import base64
import copy
import importlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tuna-sub-server'))
tuna = importlib.import_module('tuna-subscriptions')
spec = importlib.util.spec_from_file_location('enc', ROOT / 'scripts/webdav-encryption.py')
enc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(enc)


class EncryptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        cfg = copy.deepcopy(tuna.DEFAULT_CONFIG)
        cfg['database']['path'] = str(self.root / 'tuna.db')
        cfg['logging']['file'] = str(self.root / 'log')
        self.app = tuna.SubscriptionApp(cfg)
        self.addCleanup(self.app.conn.close)
        self.backup = self.root / 'backup'
        self.backup.mkdir()
        self.local = dict(name='Local', url='http://192.0.2.1:18080/', username='u', password='test-password', enc=0)
        self.remote = dict(url='https://dav.example.test/', username='other', password='test-other')

    def create(self, value):
        status, item = self.app.create_webdav_connection(value)
        self.assertEqual(status, 201)
        return item

    def sync(self, flag, backends=()):
        return enc.synchronize(self.app.db_path, [{**self.local, 'enc':flag, 'backends':list(backends)}], tuna, self.backup)

    def test_enable_disable_updates_real_subscription_and_is_idempotent(self):
        item = self.create(self.local)
        status, user = self.app.create_user({'nickname':'test-user'})
        self.assertEqual(status, 201)
        self.app.update_user_webdav(user['id'], {'enabled':True, 'connection_ids':[item['id']]})
        token = self.app.conn.execute('SELECT subscription_token FROM users').fetchone()[0]
        status, old_headers, before = self.app.get_subscription_payload(token)
        self.assertNotIn('enc=1', base64.b64decode(before).decode())
        self.assertEqual(self.sync(1), 1)
        status, headers, after = self.app.get_subscription_payload(token, old_headers['ETag'])
        self.assertEqual(status, 200)
        self.assertIn('enc=1', base64.b64decode(after).decode())
        rev = self.app.conn.execute('SELECT revision FROM users').fetchone()[0]
        self.assertEqual(self.sync(1), 0)
        self.assertEqual(rev, self.app.conn.execute('SELECT revision FROM users').fetchone()[0])
        self.assertEqual(self.sync(0), 1)
        self.assertNotIn('enc=1', base64.b64decode(self.app.get_subscription_payload(token)[2]).decode())
        row = self.app.conn.execute('SELECT * FROM webdav_connections').fetchone()
        for key in ('id','password','username','url'):
            self.assertEqual(row[key], item.get(key, self.local.get(key)))
        self.assertTrue((self.backup/'tuna.db').exists())

    def test_mixed_pool_is_not_changed_unless_all_backends_match(self):
        self.create({**self.local, 'name':'Mixed', 'backends':[self.remote]})
        self.create({**self.remote, 'name':'Foreign'})
        self.assertEqual(self.sync(1), 0)
        self.assertEqual(self.sync(1, [self.remote]), 2)

    def test_empty_database_and_wrong_credentials(self):
        self.assertEqual(self.sync(1), 0)
        self.create({**self.local,'password':'different-password'})
        self.assertEqual(self.sync(1), 0)

    def test_backup_failure_leaves_database_unchanged(self):
        self.create(self.local)
        self.backup = self.root/'missing'/'backup'
        with self.assertRaises(Exception):
            self.sync(1)
        self.assertEqual(self.app.conn.execute('SELECT enc FROM webdav_connections').fetchone()[0], 0)

    def test_restart_or_sync_failure_restores_exact_configuration(self):
        path = self.root/'config.env'
        original = b'WEBDAV_ENC="false"\nWEBDAV_PASSWORD="keep-test"\n'
        for failure in ('restart','sync'):
            path.write_bytes(original)
            restart = Mock(side_effect=[RuntimeError('start failed'),None] if failure=='restart' else None)
            sync = Mock(side_effect=RuntimeError('sync failed'))
            with self.assertRaises(RuntimeError):
                enc.apply_change(path, 'true', restart, sync)
            self.assertEqual(path.read_bytes(), original)
            self.assertEqual(restart.call_count, 2)

    def test_legacy_port_matches_runner(self):
        path = self.root/'config.env'
        path.write_text('WEBDAV_PASSWORD=test\nWEBDAV_LISTEN=:18081\nWEBDAV_ENC=true\n')
        ok, _, value = tuna.import_server_webdav_config(str(path), '192.0.2.1')
        self.assertTrue(ok)
        self.assertEqual(value['url'], 'http://192.0.2.1:18081/')
        self.assertEqual(value['enc'], 1)


if __name__ == '__main__':
    unittest.main()
