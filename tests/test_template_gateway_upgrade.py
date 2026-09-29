from contextlib import closing
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'scripts'/(name+'.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gateways = load('detect-gateways')
ports = load('plan-ports')


class TemplateGatewayUpgrade(unittest.TestCase):
    def fixture(self, root, socks_port=10808):
        path = root/'etc/x-ui/x-ui.db'
        path.parent.mkdir(parents=True)
        template = {'inbounds': [
            {'tag': 'in-mieru-socks', 'protocol': 'socks', 'listen': '127.0.0.1',
             'port': socks_port, 'settings': {'auth': 'noauth', 'udp': True}},
            {'tag': 'in-snell-redirect', 'protocol': 'dokodemo-door', 'listen': '127.0.0.1',
             'port': 12346, 'settings': {'network': 'tcp,udp', 'followRedirect': True}},
        ], 'routing': {'balancers': [{'tag': 'keep', 'fallbackTag': 'existing'}]}}
        with closing(sqlite3.connect(path)) as db, db:
            db.execute('CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)')
            db.execute('CREATE TABLE settings (key, value)')
            db.execute('INSERT INTO settings VALUES (?,?)', ('xrayTemplateConfig', json.dumps(template)))
            db.execute('INSERT INTO inbounds (enable,listen,port,protocol,settings,stream_settings,tag) VALUES (?,?,?,?,?,?,?)',
                       (1,'127.0.0.1',12345,'dokodemo-door','{"network":"tcp,udp","followRedirect":true}','{"sockopt":{"tproxy":"tproxy"}}','existing-tproxy'))
        return path

    def dump(self, path):
        with closing(sqlite3.connect(path)) as db, db:
            return list(db.iterdump())

    def test_existing_template_gateways_preserved_and_repeat_stable(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            root=Path(tmp); db=self.fixture(root); before=self.dump(db)
            for _ in range(2):
                planned=ports.plan(root)
                self.assertEqual([planned['XRAY_'+k+'_PORT'] for k in ('SOCKS','TPROXY','REDIRECT')],[10808,12345,12346])
                result=gateways.configure(str(db))
                self.assertIn('FOUND_SOCKS=10808',result)
                self.assertNotIn('RELOAD_XUI=1',result)
                self.assertEqual(self.dump(db),before)

    def test_nonstandard_template_port_is_discovered(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            root=Path(tmp);db=self.fixture(root,21081)
            self.assertEqual(ports.plan(root)['XRAY_SOCKS_PORT'],21081)
            self.assertIn('FOUND_SOCKS=21081',gateways.configure(str(db)))

    def test_saved_conflict_is_rejected_without_writes(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            root=Path(tmp);db=self.fixture(root)
            saved=root/'etc/x-manager/gateways.env';saved.parent.mkdir();saved.write_text('XRAY_SOCKS_PORT=21081\n')
            before=self.dump(db)
            with self.assertRaises(ValueError):ports.plan(root)
            self.assertEqual(self.dump(db),before)

    def test_ambiguous_template_requires_explicit_selection(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            root=Path(tmp);db=self.fixture(root)
            with closing(sqlite3.connect(db)) as conn, conn:
                data=json.loads(conn.execute('SELECT value FROM settings').fetchone()[0])
                second=dict(data['inbounds'][0],port=21081,tag='second-socks')
                data['inbounds'].append(second)
                conn.execute('UPDATE settings SET value=?',(json.dumps(data),))
            before=self.dump(db)
            with self.assertRaises(ValueError):gateways.configure(str(db))
            with patch.dict(os.environ, {'XRAY_SOCKS_PORT':'21081'}):
                self.assertIn('FOUND_SOCKS=21081',gateways.configure(str(db)))
            self.assertEqual(self.dump(db),before)

    def test_incompatible_socks_is_not_changed_or_replaced(self):
        for change in ({'auth':'password','udp':True},{'auth':'noauth','udp':False}):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
                db=self.fixture(Path(tmp))
                with closing(sqlite3.connect(db)) as conn, conn:
                    data=json.loads(conn.execute('SELECT value FROM settings').fetchone()[0])
                    data['inbounds'][0]['settings']=change
                    conn.execute('UPDATE settings SET value=?',(json.dumps(data),))
                before=self.dump(db)
                with self.assertRaises(ValueError):gateways.configure(str(db))
                self.assertEqual(self.dump(db),before)
