"""Local delivery selection: exact ownership, immutable storage, coherent snapshots."""
import base64
import copy
import importlib
import json
import pathlib
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
tuna = importlib.import_module('tuna-subscriptions')


class SnellSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.marker = pathlib.Path(self.tmp.name, 'snell-active.json')
        self.marker_patch = patch.object(tuna, 'SNELL_SELECTION_FILE', str(self.marker))
        self.marker_patch.start()
        self.control_dirs = tuple(pathlib.Path(self.tmp.name, name) for name in ('off', 'stopped'))
        for directory in self.control_dirs:
            directory.mkdir()
        self.control_patch = patch.object(tuna, 'SNELL_SERVICE_CONTROL_DIRS', self.control_dirs)
        self.control_patch.start()
        config = copy.deepcopy(tuna.DEFAULT_CONFIG)
        config['database']['path'] = str(pathlib.Path(self.tmp.name, 'test.db'))
        config['logging']['file'] = str(pathlib.Path(self.tmp.name, 'service.log'))
        self.app = tuna.SubscriptionApp(config)
        self.links = {
            'local5': 'snell://shared-psk@local.test:443?version=4#Local-v5',
            'local6a': 'snell://shared-psk@local.test:444?version=6#Local-v6-a',
            'local6b': 'snell://shared-psk@local.test:445?version=6#Local-v6-b',
            'foreign5': 'snell://foreign@remote.test:443?version=4#Remote-v5',
            'foreign6': 'snell://foreign@remote.test:444?version=6#Remote-v6',
            # Same local endpoint/PSK but a different exact snapshot stays foreign.
            'manual6': 'snell://shared-psk@local.test:444?version=6#Manual-name',
        }
        status, self.user = self.app.create_user({
            'nickname': 'Stable user', 'snell_uri': '\n'.join(self.links.values()),
            'custom_uri': 'vless://unchanged@other.test:443#Other-protocol',
        })
        self.assertEqual(status, 201)
        self.app.conn.executescript('''
            CREATE TABLE x_manager_snell_links (
                user_id TEXT, uri TEXT, follow_name INTEGER, PRIMARY KEY(user_id,uri));
            CREATE TABLE x_manager_snell_endpoint_links (
                endpoint_id TEXT,user_id TEXT,uri TEXT,follow_name INTEGER,
                PRIMARY KEY(endpoint_id,user_id,uri));
        ''')
        self.app.conn.execute('INSERT INTO x_manager_snell_links VALUES (?,?,1)',
                              (self.user['id'], self.links['local5']))
        for endpoint, name in [('a' * 32, 'local6a'), ('b' * 32, 'local6b')]:
            self.app.conn.execute('INSERT INTO x_manager_snell_endpoint_links VALUES (?,?,?,1)',
                                  (endpoint, self.user['id'], self.links[name]))
        # A different user's binding must not acquire this user's foreign link.
        self.app.conn.execute('INSERT INTO x_manager_snell_links VALUES (?,?,1)',
                              ('another-user', self.links['foreign5']))
        self.app.conn.commit()
        self.document = {
            'profiles': [dict(id=pid, name='Name ' + pid, uri=uri) for pid, uri in self.links.items()],
            'groups': [
                dict(id='all', name='All stable candidates', category='VPN', family='VPN',
                     type='URL_TEST', memberIds=list(self.links), routingProfileId='foreign5'),
                dict(id='small', name='Small group', category='VPN', family='VPN',
                     type='URL_TEST', memberIds=['local5', 'local6a'], routingProfileId='local5'),
                dict(id='source6', name='Source must stay', category='VPN', family='VPN',
                     type='URL_TEST', memberIds=['foreign5', 'foreign6', 'local6a'], routingProfileId='local6a'),
            ],
        }
        status, _ = self.app.connection_groups.save(self.user['id'], dict(self.document, expectedRevision=1))
        self.assertEqual(status, 200)
        self.stored = '\n'.join(self.app.conn.iterdump())

    def tearDown(self):
        try:
            self.assertEqual('\n'.join(self.app.conn.iterdump()), self.stored)
        finally:
            self.app.conn.close()
            self.marker_patch.stop()
            self.control_patch.stop()
            self.tmp.cleanup()

    def select(self, version, slot='1', endpoint='a' * 32):
        state = dict(format=1, version=version, slot=None if version == 5 else slot,
                     unit='snell.service' if version == 5 else 'snell6@' + slot + '.service',
                     endpoint_id=None if version == 5 else endpoint)
        self.marker.write_text(json.dumps(state), encoding='utf-8')

    def plain(self, etag=None):
        status, headers, body = self.app.get_subscription_payload(self.user['token'], etag)
        return status, headers, base64.b64decode(body).decode().splitlines() if body else []

    def structured(self):
        status, headers, body = self.app.connection_groups.publish(self.user['token'])
        self.assertEqual(status, 200)
        return headers, json.loads(body)

    def test_missing_marker_preserves_legacy_delivery(self):
        status, _, lines = self.plain()
        self.assertEqual(status, 200)
        self.assertTrue(set(self.links.values()).issubset(lines))
        _, document = self.structured()
        self.assertEqual({p['id'] for p in document['profiles']}, set(self.links))
        self.assertEqual(len(document['groups']), 3)

    def test_plain_removal_keeps_group_provenance_and_inactive_v6_hidden(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('removal_endpoints', ROOT.parent / 'scripts/snell6-endpoints.py')
        endpoints = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(endpoints)
        self.select(5)
        link = self.links['local6a']
        before = self.structured()[1]
        path = self.app.conn.execute('PRAGMA database_list').fetchone()[2]
        try:
            endpoints.remove_subscription_link(path, self.user['id'], link)
            self.assertNotIn(link, self.plain()[2])
            after = self.structured()[1]
            self.assertEqual(after['profiles'], before['profiles'])
            self.assertEqual(after['groups'], before['groups'])
            saved = self.app.conn.execute('SELECT document_json FROM user_connection_groups WHERE user_id=?', (self.user['id'],)).fetchone()[0]
            self.assertIn(link, [p['uri'] for p in json.loads(saved)['profiles']])
            self.assertIsNotNone(self.app.conn.execute('SELECT 1 FROM x_manager_snell_endpoint_links WHERE user_id=? AND uri=?', (self.user['id'], link)).fetchone())
        finally:
            self.stored = '\n'.join(self.app.conn.iterdump())

    def test_v5_filters_owned_v6_only_and_preserves_other_protocol(self):
        self.select(5)
        status, _, lines = self.plain()
        self.assertEqual(status, 200)
        self.assertNotIn(self.links['local6a'], lines)
        self.assertNotIn(self.links['local6b'], lines)
        for name in ('local5', 'foreign5', 'foreign6', 'manual6'):
            self.assertIn(self.links[name], lines)
        self.assertIn('vless://unchanged@other.test:443#Other-protocol', lines)

    def test_switches_version_and_endpoint_without_revision_change(self):
        self.select(5)
        _, first, _ = self.plain()
        first_groups, _ = self.structured()
        self.assertEqual(self.plain(first['ETag'])[0], 304)
        self.select(6)
        status, second, lines = self.plain(first['ETag'])
        second_groups, _ = self.structured()
        self.assertEqual(status, 200)
        self.assertNotEqual(first['ETag'], second['ETag'])
        self.assertNotEqual(first_groups['ETag'], second_groups['ETag'])
        self.assertIn(self.links['local6a'], lines)
        self.assertNotIn(self.links['local5'], lines)
        self.assertNotIn(self.links['local6b'], lines)
        for name in ('foreign5', 'foreign6', 'manual6'):
            self.assertIn(self.links[name], lines)
        self.select(6, '2', 'b' * 32)
        status, third, lines = self.plain(second['ETag'])
        self.assertEqual(status, 200)
        self.assertNotEqual(second['ETag'], third['ETag'])
        self.assertIn(self.links['local6b'], lines)
        self.assertNotIn(self.links['local6a'], lines)
        self.select(5)
        self.assertEqual(self.plain()[1]['ETag'], first['ETag'])

    def test_group_members_and_source_route_remain_consistent(self):
        self.select(5)
        _, document = self.structured()
        self.assertEqual([g['id'] for g in document['groups']], ['all'])
        group = document['groups'][0]
        self.assertEqual(group['name'], 'All stable candidates')
        self.assertEqual(group['routingProfileId'], 'foreign5')
        self.assertEqual(group['memberIds'], ['local5', 'foreign5', 'foreign6', 'manual6'])
        self.assertEqual({p['id'] for p in document['profiles']}, set(group['memberIds']))
        self.select(6)
        _, document = self.structured()
        self.assertEqual([g['id'] for g in document['groups']], ['all', 'source6'])
        ids = {p['id'] for p in document['profiles']}
        for group in document['groups']:
            self.assertTrue(set(group['memberIds']).issubset(ids))
            self.assertIn(group['routingProfileId'], group['memberIds'])

    def test_group_container_transports_same_filtered_document(self):
        self.select(6)
        _, expected = self.structured()
        status, headers, body = self.app.connection_groups.publish_uri(self.user['token'])
        self.assertEqual(status, 200)
        self.assertIn('ETag', headers)
        line = base64.b64decode(body).decode().strip()
        payload = line.removeprefix(tuna.GROUP_URI_PREFIX)
        self.assertEqual(json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))), expected)
        self.select(5)
        self.assertNotEqual(self.app.connection_groups.publish_uri(self.user['token'])[1]['ETag'], headers['ETag'])

    def test_invalid_marker_fails_closed_without_exposing_its_contents(self):
        invalid = ['not-json-secret', '[]', '{}',
                   json.dumps(dict(format=True, version=5, unit='snell.service')),
                   json.dumps(dict(format=1, version=6, slot='1', unit='snell.service', endpoint_id='a' * 32)),
                   json.dumps(dict(format=1, version=6, slot='1', unit='snell6@1.service', endpoint_id='secret'))]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.marker.write_text(raw)
                for publish in (self.app.get_subscription_payload, self.app.connection_groups.publish,
                                self.app.connection_groups.publish_uri):
                    status, headers, body = publish(self.user['token'])
                    self.assertEqual(status, 500)
                    self.assertEqual(body, b'')
                    self.assertNotIn('secret', json.dumps(headers))

    def test_marker_without_binding_tables_does_not_guess_ownership(self):
        self.app.conn.execute('DROP TABLE x_manager_snell_links')
        self.app.conn.execute('DROP TABLE x_manager_snell_endpoint_links')
        self.app.conn.commit()
        self.stored = '\n'.join(self.app.conn.iterdump())
        self.select(5)
        status, first, lines = self.plain()
        self.assertEqual(status, 200)
        self.assertTrue(set(self.links.values()).issubset(lines))
        self.select(6)
        _, second, other_lines = self.plain()
        self.assertEqual(lines, other_lines)
        self.assertNotEqual(first['ETag'], second['ETag'])

    def test_http_selection_conditional_requests_and_invalid_marker(self):
        server = tuna.ThreadingHTTPServer(('127.0.0.1', 0), tuna.SubscriptionRequestHandler)
        server.app = self.app
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for prefix in ('sub', 'sub-json', 'sub-groups'):
                with self.subTest(prefix=prefix):
                    url = 'http://127.0.0.1:%d/%s/%s' % (server.server_port, prefix, self.user['token'])
                    self.select(5)
                    with urllib.request.urlopen(url) as response:
                        self.assertEqual(response.status, 200)
                        first_body = response.read()
                        etag = response.headers['ETag']
                    request = urllib.request.Request(url, headers={'If-None-Match': etag})
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        urllib.request.urlopen(request)
                    self.assertEqual(caught.exception.code, 304)
                    caught.exception.close()
                    self.select(6)
                    with urllib.request.urlopen(request) as response:
                        self.assertEqual(response.status, 200)
                        self.assertNotEqual(response.headers['ETag'], etag)
                        self.assertNotEqual(response.read(), first_body)
                    self.marker.write_text('broken-marker-private-content')
                    with self.assertRaises(urllib.error.HTTPError) as caught:
                        urllib.request.urlopen(url)
                    self.assertEqual(caught.exception.code, 500)
                    self.assertNotIn(b'private-content', caught.exception.read())
                    caught.exception.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_legacy_owned_v5_query_is_projected_without_storage_or_foreign_changes(self):
        local = 'snell://escaped%2Bpsk@local.test:443?reuse=0&version=5&custom=a%2Bb%20c#Saved%20name'
        foreign = 'snell://foreign@remote.test:443?version=5#Foreign-v5'
        status, user = self.app.create_user({'nickname': 'Legacy links', 'snell_uri': local + '\n' + foreign})
        self.assertEqual(status, 201)
        self.app.conn.execute('INSERT INTO x_manager_snell_links VALUES (?,?,1)', (user['id'], local))
        self.app.conn.commit()
        document = dict(profiles=[dict(id='local', name='Stored local name', uri=local),
                                  dict(id='foreign', name='Stored foreign name', uri=foreign)],
                        groups=[dict(id='source', name='Stable group', category='VPN', family='VPN',
                                     type='URL_TEST', memberIds=['local', 'foreign'], routingProfileId='local')])
        self.assertEqual(self.app.connection_groups.save(user['id'], dict(document, expectedRevision=1))[0], 200)
        self.stored = '\n'.join(self.app.conn.iterdump())
        # Until the operator selects a version, the legacy bytes still pass through.
        self.assertIn(local, base64.b64decode(self.app.get_subscription_payload(user['token'])[2]).decode())
        self.select(5)
        status, _, body = self.app.get_subscription_payload(user['token'])
        self.assertEqual(status, 200)
        expected = local.replace('&version=5&', '&version=4&')
        self.assertEqual(base64.b64decode(body).decode().splitlines(), [expected, foreign])
        status, _, body = self.app.connection_groups.publish(user['token'])
        self.assertEqual(status, 200)
        published = json.loads(body)
        self.assertEqual(published['profiles'], [dict(document['profiles'][0], uri=expected), document['profiles'][1]])
        self.assertEqual(published['groups'][0]['routingProfileId'], 'local')
        self.assertEqual(published['groups'][0]['memberIds'], ['local', 'foreign'])
        status, _, body = self.app.connection_groups.publish_uri(user['token'])
        self.assertEqual(status, 200)
        payload = base64.b64decode(body).decode().strip().removeprefix(tuna.GROUP_URI_PREFIX)
        self.assertEqual(json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))), published)

    def test_off_and_stopped_markers_suppress_all_owned_links_and_change_etags(self):
        for version in (5, 6):
            self.select(version)
            unit = 'snell.service' if version == 5 else 'snell6@1.service'
            for directory in self.control_dirs:
                with self.subTest(version=version, control=directory.name):
                    _, first, first_lines = self.plain()
                    first_groups, first_document = self.structured()
                    first_container = self.app.connection_groups.publish_uri(self.user['token'])
                    marker = directory / unit
                    marker.touch()
                    try:
                        status, second, lines = self.plain(first['ETag'])
                        self.assertEqual(status, 200)
                        self.assertNotEqual(first['ETag'], second['ETag'])
                        for name in ('local5', 'local6a', 'local6b'):
                            self.assertNotIn(self.links[name], lines)
                        for name in ('foreign5', 'foreign6', 'manual6'):
                            self.assertIn(self.links[name], lines)
                        second_groups, document = self.structured()
                        self.assertNotEqual(first_groups['ETag'], second_groups['ETag'])
                        self.assertNotEqual(first_document, document)
                        self.assertEqual({p['id'] for p in document['profiles']}, {'foreign5', 'foreign6', 'manual6'})
                        self.assertEqual([g['id'] for g in document['groups']], ['all'])
                        second_container = self.app.connection_groups.publish_uri(self.user['token'])
                        self.assertNotEqual(first_container[1]['ETag'], second_container[1]['ETag'])
                        self.assertNotEqual(first_container[2], second_container[2])
                    finally:
                        marker.unlink()
                    _, restored, restored_lines = self.plain()
                    self.assertEqual(restored['ETag'], first['ETag'])
                    self.assertEqual(restored_lines, first_lines)

    def test_service_markers_for_other_units_and_missing_selection_do_not_filter(self):
        for directory in self.control_dirs:
            (directory / 'snell6@2.service').touch()
        self.assertTrue(set(self.links.values()).issubset(self.plain()[2]))
        self.select(6)
        self.assertIn(self.links['local6a'], self.plain()[2])


if __name__ == '__main__':
    unittest.main()
