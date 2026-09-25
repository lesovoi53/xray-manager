import copy
import hashlib
import importlib
import io
import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
tuna = importlib.import_module('tuna-subscriptions')
groups = importlib.import_module('tuna_connection_groups')
FIXTURE = json.loads((ROOT / 'fixtures/group-subscription-demo.json').read_text())


class ConnectionGroupsTests(unittest.TestCase):
    def test_speedtest_blank_url_reprompts_and_settings_use_choices(self):
        tui = importlib.import_module('tuna-groups')
        output = io.StringIO()
        with patch('builtins.input', side_effect=['', 'http://invalid.test/file', 'https://example.test/file']), redirect_stdout(output):
            self.assertEqual(tui.test_url('SPEEDTEST'), 'https://example.test/file')
        self.assertIn('непустой HTTPS URL', output.getvalue())
        group = dict(groups.DEFAULTS, type='URL_TEST', testOnConnect=True, testUrl='https://example.test/probe')
        with patch('builtins.input', side_effect=['1', '2', '0']), redirect_stdout(io.StringIO()):
            tui.settings(group)
        self.assertEqual(group['selectionMode'], 'PRIORITY')

    def test_import_reuses_existing_uris_and_does_not_change_user(self):
        tui = importlib.import_module('tuna-groups')
        server = tuna.ThreadingHTTPServer(('127.0.0.1', 0), tuna.SubscriptionRequestHandler)
        server.app = self.app
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        state = self.store.editor(self.user['id'])[1]
        try:
            base = 'http://127.0.0.1:%d' % server.server_port
            with redirect_stdout(io.StringIO()):
                tui.import_profiles(base, '/api/users/'+self.user['id'], state)
                first = copy.deepcopy(state['profiles'])
                tui.import_profiles(base, '/api/users/'+self.user['id'], state)
            self.assertEqual(state['profiles'], first)
            self.assertEqual(first[0]['uri'], FIXTURE['profiles'][0]['uri'])
            self.assertEqual(self.store.editor(self.user['id'])[1]['profiles'], [])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        config = copy.deepcopy(tuna.DEFAULT_CONFIG)
        config['database']['path'] = self.tmp.name + '/test.db'
        config['logging']['file'] = self.tmp.name + '/service.log'
        config['server']['bind_address'] = '127.0.0.1'
        self.app = tuna.SubscriptionApp(config)
        status, self.user = self.app.create_user({'nickname': 'Fixture user', 'custom_uri': FIXTURE['profiles'][0]['uri']})
        self.assertEqual(status, 201)
        self.store = self.app.connection_groups
        self.document = copy.deepcopy({k: FIXTURE[k] for k in ('profiles', 'groups')})

    def tearDown(self):
        self.app.conn.close()
        self.tmp.cleanup()

    def save(self, document=None, revision=None, user=None):
        user = user or self.user
        if revision is None:
            revision = self.store.editor(user['id'])[1]['revision']
        return self.store.save(user['id'], dict(document or self.document, expectedRevision=revision))

    def publish(self):
        status, headers, body = self.store.publish(self.user['token'])
        self.assertEqual(status, 200)
        self.assertEqual(headers['Content-Type'], 'application/json; charset=utf-8')
        return json.loads(body)

    def test_client_fixture_roundtrip_all_protocols_and_families(self):
        self.assertEqual(self.save()[0], 200)
        actual = self.publish()
        expected = copy.deepcopy(FIXTURE)
        expected.update(subscriptionId=self.user['id'], revision=2, name=self.user['nickname'])
        self.assertEqual(actual, expected)
        self.assertEqual(len(actual['profiles']), 14)
        self.assertEqual(len(actual['groups']), 8)

    def test_modes_strategies_and_all_settings_are_retained(self):
        for group in self.document['groups']:
            group['selectionMode'] = 'PRIORITY'
            group['memberIds'].reverse()
            group.update(samples=5, durationSeconds=30, improvementMs=321, improvementPercent=1000,
                         automatic=True, allowMobile=True, testOnConnect=False, maxBytesPerCandidate=1073741824)
        self.assertEqual(self.save()[0], 200)
        self.assertEqual(self.publish()['groups'], self.document['groups'])
        changed = copy.deepcopy(self.document)
        changed['groups'][0]['type'] = 'SPEEDTEST'
        changed['groups'][0]['probeMethod'] = 'GET'
        self.assertEqual(self.save(changed)[0], 200)
        result = self.publish()['groups'][0]
        self.assertEqual(result['samples'], 5)
        self.assertEqual(result['improvementMs'], 321)
        self.assertEqual(result['id'], self.document['groups'][0]['id'])

    def test_invalid_changes_roll_back_and_do_not_disclose_input(self):
        self.assertEqual(self.save()[0], 200)
        baseline = self.store.editor(self.user['id'])[1]
        mutations = [
            lambda d: d['groups'][0].update(family='WEBDAV'),
            lambda d: d['groups'][0].update(category='BYPASS'),
            lambda d: d['groups'][0].update(memberIds=['unknown', 'vless']),
            lambda d: d['groups'][0].update(memberIds=['vless', 'vless']),
            lambda d: d['groups'][0].update(memberIds=['vless']),
            lambda d: d['groups'][0].update(routingProfileId='webdav-1'),
            lambda d: d['groups'][0].update(selectionMode='MANUAL'),
            lambda d: d['groups'][0].update(type='SPEEDTEST', probeMethod='HEAD'),
            lambda d: d['groups'][0].update(testUrl='https://secret:password@example.invalid/file'),
            lambda d: d['groups'][0].update(testUrl='https://example.invalid/file#'),
            lambda d: d['groups'][0].update(automatic='true'),
            lambda d: d['groups'][0].update(timeoutSeconds=True),
            lambda d: d['groups'][0].update(family=[]),
            lambda d: d['profiles'][0].update(uri='stormdns://private-secret'),
            lambda d: d['profiles'].append(copy.deepcopy(d['profiles'][0])),
            lambda d: d['groups'].append(copy.deepcopy(d['groups'][0])),
            lambda d: d['groups'][0].update(name='😀' * 101),
        ]
        for field, (minimum, maximum) in groups.RANGES.items():
            mutations.extend([lambda d, f=field, v=minimum - 1: d['groups'][0].update({f: v}),
                              lambda d, f=field, v=maximum + 1: d['groups'][0].update({f: v})])
        for change in mutations:
            with self.subTest(change=change):
                invalid = copy.deepcopy(self.document)
                change(invalid)
                status, response = self.save(invalid)
                self.assertEqual(status, 400)
                self.assertNotIn('secret', json.dumps(response))
                self.assertEqual(self.store.editor(self.user['id'])[1], baseline)

    def test_idempotence_rename_credentials_and_shared_profile(self):
        self.assertEqual(self.save()[0], 200)
        first = self.publish()
        status, result = self.save(revision=1)  # Retry the identical previous request.
        self.assertEqual(status, 200)
        self.assertFalse(result['changed'])
        self.assertEqual(result['revision'], 2)
        edited = copy.deepcopy(self.document)
        edited['groups'][0]['name'] = 'Переименована'
        edited['profiles'][0]['uri'] += '&unknown-preserved=abc%2Bdef'
        self.assertEqual(self.save(edited)[0], 200)
        second = self.publish()
        self.assertEqual(first['subscriptionId'], second['subscriptionId'])
        self.assertEqual([p['id'] for p in first['profiles']], [p['id'] for p in second['profiles']])
        self.assertEqual(len(second['profiles']), 14)
        self.assertEqual(second['profiles'][0]['uri'], edited['profiles'][0]['uri'])
        self.assertGreater(second['revision'], first['revision'])
        self.assertEqual(self.save(self.document, revision=1)[0], 409)

    def test_deletion_and_exclusion_have_no_dangling_references(self):
        self.assertEqual(self.save()[0], 200)
        for group in self.document['groups']:
            if 'anytls' in group['memberIds']:
                group['memberIds'].remove('anytls')
                if group['routingProfileId'] == 'anytls':
                    group['routingProfileId'] = group['memberIds'][0]
        self.document['profiles'] = [p for p in self.document['profiles'] if p['id'] != 'anytls']
        self.document['groups'][0]['enabled'] = False
        self.document['groups'].pop()
        self.assertEqual(self.save()[0], 200)
        result = self.publish()
        ids = {p['id'] for p in result['profiles']}
        self.assertNotIn('anytls', ids)
        self.assertEqual(len(result['groups']), 6)
        for group in result['groups']:
            self.assertTrue(set(group['memberIds']).issubset(ids))

    def test_user_isolation_and_legacy_subscription_unchanged(self):
        legacy_before = self.app.get_subscription_payload(self.user['token'])[2]
        self.assertEqual(self.save()[0], 200)
        status, other = self.app.create_user({'nickname': 'Other'})
        self.assertEqual(status, 201)
        status, _, body = self.store.publish(other['token'])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['profiles'], [])
        self.assertEqual(json.loads(body)['groups'], [])
        self.assertEqual(self.app.get_subscription_payload(self.user['token'])[2], legacy_before)
        self.assertEqual(self.store.publish('not-a-token')[0], 404)
        self.app.conn.execute('UPDATE users SET enabled=0 WHERE id=?', (self.user['id'],))
        self.app.conn.commit()
        self.assertEqual(self.store.publish(self.user['token'])[0], 404)

    def test_limits_and_corrupt_snapshot_fail_closed(self):
        self.assertEqual(self.save()[0], 200)
        oversized = copy.deepcopy(self.document)
        oversized['profiles'][0]['uri'] += '?padding=' + 'x' * groups.MAX_BODY
        self.assertEqual(self.save(oversized)[0], 400)
        duplicate = copy.deepcopy(self.document)
        duplicate['groups'] *= 13
        self.assertEqual(self.save(duplicate)[0], 400)
        with self.app.conn:
            self.app.conn.execute('UPDATE user_connection_groups SET document_json=? WHERE user_id=?', ('{}', self.user['id']))
        status, _, body = self.store.publish(self.user['token'])
        self.assertEqual(status, 500)
        self.assertEqual(body, b'')

    def test_http_json_and_token_redaction(self):
        self.assertEqual(self.save()[0], 200)
        server = tuna.ThreadingHTTPServer(('127.0.0.1', 0), tuna.SubscriptionRequestHandler)
        server.app = self.app
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = 'http://127.0.0.1:%d/sub-json/%s' % (server.server_port, self.user['token'])
            with urllib.request.urlopen(url) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers['Content-Type'], 'application/json; charset=utf-8')
                self.assertEqual(json.load(response)['schema'], 'tuna.subscription')
            log = pathlib.Path(self.app.config['logging']['file']).read_text()
            self.assertNotIn(self.user['token'], log)
            self.assertNotIn(self.document['profiles'][0]['uri'], log)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_tui_create_rename_reorder_and_disable_over_http(self):
        server = tuna.ThreadingHTTPServer(('127.0.0.1', 0), tuna.SubscriptionRequestHandler)
        server.app = self.app
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        uri1 = 'vless://11111111-2222-4333-8444-555555555555@192.0.2.1:24443?security=tls#One'
        uri2 = 'vless://11111111-2222-4333-8444-555555555556@192.0.2.2:24443?security=tls#Two'
        def run_tui(answers):
            result = subprocess.run([sys.executable, str(ROOT / 'tuna-groups.py'), self.user['id'],
                                     '--api', 'http://127.0.0.1:%d' % server.server_port],
                                    input='\n'.join(answers) + '\n', text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn('Изменения не сохранены', result.stdout)
            self.assertNotIn(uri1, result.stdout)
            self.assertNotIn(uri2, result.stdout)
        try:
            run_tui(['1', '1', 'TUI fixture', '1', '1', '1', uri1, '1', uri2, '3', '1', '0', '1', '0'])
            before = self.store.editor(self.user['id'])[1]
            self.assertEqual(len(before['groups']), 1)
            run_tui(['3', '1', 'Renamed', '1', '2', '1', '2', '2', '1', '0', '1', '0'])
            after = self.store.editor(self.user['id'])[1]
            self.assertEqual(after['groups'][0]['id'], before['groups'][0]['id'])
            self.assertEqual(after['groups'][0]['name'], 'Renamed')
            self.assertEqual(after['groups'][0]['memberIds'], before['groups'][0]['memberIds'][::-1])
            self.assertEqual(len(self.publish()['groups']), 1)
            run_tui(['4', '1', 'y', '0'])
            self.assertEqual(self.publish()['groups'], [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == '__main__':
    unittest.main()
