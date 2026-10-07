import importlib.util
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('snell_subscriptions', ROOT/'scripts/snell-subscriptions.py')
snell = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snell)


class SnellSubscriptions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root/'snell-server.conf'
        self.config.write_text('[snell-server]\nlisten = 0.0.0.0:19552\npsk = synthetic-key\nobfs = http\nobfs-host = yandex.ru\n')
        self.tag = self.root/'tag.txt'
        self.tag.write_text('Local name & test\n')
        self.dbpath = self.root/'subscriptions.db'
        self.db = sqlite3.connect(self.dbpath)
        self.addCleanup(self.db.close)
        self.db.execute('CREATE TABLE users (id TEXT PRIMARY KEY,snell_uri TEXT,revision INTEGER,updated_at TEXT,subscription_token TEXT,mieru_uri TEXT)')
        self.db.execute('CREATE TABLE user_connection_groups (user_id TEXT PRIMARY KEY,document_json TEXT)')
        self.old = 'snell://synthetic-key@192.0.2.1:19552/?version=5&reuse=true&tfo=true#Snell-v5'
        self.foreign = 'snell://external-key@198.51.100.1:9999/?version=5&reuse=false#Foreign'
        self.db.execute('INSERT INTO users VALUES (?,?,?,?,?,?)', ('local', self.old+'\n'+self.foreign, 5, 'old', 'synthetic-token', 'untouched-mieru'))
        self.db.execute('INSERT INTO users VALUES (?,?,?,?,?,?)', ('manual', self.old, 2, 'old', 'other-token', 'other-mieru'))
        self.document = {'profiles': [{'id': 'keep-profile-id', 'name': 'My alias', 'uri': self.old}], 'groups': []}
        self.db.execute('INSERT INTO user_connection_groups VALUES (?,?)', ('local',json.dumps(self.document)))
        self.db.commit()

    def value(self):
        return snell.settings(self.config, self.tag)

    def sync(self, **kwargs):
        with self.db:
            return snell.synchronize(self.db, self.value(), '192.0.2.1', **kwargs)

    def local(self):
        return self.db.execute('SELECT * FROM users WHERE id="local"').fetchone()

    def v6(self, **changes):
        return dict(dict(version=6, mode='default', port=20000,
                         psk='test@key:/?#&%+ ключ', name='IPv6 & новое имя'), **changes)

    def sync6(self, value, **kwargs):
        with self.db:
            return snell.synchronize(self.db, value, '192.0.2.1', endpoint_id='local-v6', **kwargs)

    def test_v6_encoding_and_flags(self):
        value = self.v6()
        link = snell.uri(value, '2001:db8::1')
        p = urlsplit(link)
        self.assertEqual(p.hostname, '2001:db8::1')
        self.assertEqual(unquote(p.username), value['psk'])
        self.assertEqual(unquote(p.fragment), value['name'])
        q = parse_qs(p.query)
        self.assertEqual(q['version'], ['6'])
        self.assertEqual(q['mode'], ['default'])
        self.assertNotIn('obfs-mode', q)
        previous = link.replace('reuse=true', 'reuse=false')
        previous = previous.replace('#', '&network=auto&userkey=a%2Bb#')
        updated = snell.uri(self.v6(name='Renamed'), '2001:db8::1', previous, False)
        self.assertEqual(parse_qs(urlsplit(updated).query)['userkey'], ['a+b'])
        self.assertEqual(parse_qs(urlsplit(updated).query)['reuse'], ['false'])
        self.assertEqual(urlsplit(updated).fragment, p.fragment)

    def test_v6_rejects_incompatible_parameters(self):
        good = snell.uri(self.v6(), '192.0.2.1')
        for extra in ('obfs-mode=none', 'obfs-host=example.invalid', 'obfs=http',
                      'version=5', 'quic-proxy-mode=true', 'reuse=maybe',
                      'mode=bogus', 'network=udp&udp-relay=false', 'unknown=x'):
            with self.subTest(extra=extra), self.assertRaises(snell.Error):
                snell.uri(self.v6(), '192.0.2.1', good.replace('#', '&'+extra+'#'))
        for value in (self.v6(mode='bogus'), self.v6(obfs='http'), self.v6(port=0),
                      self.v6(name='bad\nname'), self.v6(version=7), self.v6(version=5)):
            with self.assertRaises(snell.Error):
                snell.uri(value, '192.0.2.1')
        with self.assertRaises(snell.Error):
            snell.uri(self.v6(), '192.0.2.1', self.old)

    def test_v6_sync_preserves_v5_foreign_groups_and_is_idempotent(self):
        self.sync(bind_user='local', adopt=True)
        original = self.local()
        value = self.v6()
        link = snell.uri(value, '192.0.2.1')
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"', (original[1]+'\n'+link,))
        doc = {'profiles':[{'id':'v6-id','name':'Keep alias','uri':link}], 'groups':[{'id':'keep-group'}]}
        self.db.execute('UPDATE user_connection_groups SET document_json=? WHERE user_id="local"', (json.dumps(doc),))
        self.db.commit()
        self.assertEqual(self.sync6(value, bind_user='local'), 0)
        self.assertEqual(self.sync6(self.v6(name='New v6')), 1)
        after = self.local()
        self.assertEqual(after[1].splitlines()[:2], original[1].splitlines())
        self.assertEqual(after[2], original[2]+1)
        self.assertEqual(after[4:], original[4:])
        stored = json.loads(self.db.execute('SELECT document_json FROM user_connection_groups WHERE user_id="local"').fetchone()[0])
        self.assertEqual(stored['profiles'][0]['id'], 'v6-id')
        self.assertEqual(stored['profiles'][0]['name'], 'Keep alias')
        self.assertEqual(stored['groups'], doc['groups'])
        self.assertEqual(self.sync6(self.v6(name='New v6')), 0)
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.local(), after)
        self.assertEqual(self.db.execute('SELECT count(*) FROM x_manager_snell_endpoint_links').fetchone()[0], 1)

    def test_v6_requires_scope_and_does_not_adopt(self):
        before = self.local()
        with self.assertRaises(snell.Error), self.db:
            snell.synchronize(self.db, self.v6(), '192.0.2.1')
        with self.assertRaises(snell.Error):
            self.sync6(self.v6(), bind_user='local', adopt=True)
        self.assertEqual(before, self.local())

    def test_v6_endpoint_isolation(self):
        a, b = self.v6(), self.v6(port=20001, name='Second')
        first, second = snell.uri(a, '192.0.2.1'), snell.uri(b, '192.0.2.1')
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"', (first+'\n'+second,))
        self.db.commit()
        self.sync6(a, bind_user='local')
        with self.assertRaises(snell.Error), self.db:
            snell.synchronize(self.db, a, '192.0.2.1', endpoint_id='second', bind_user='local')
        with self.db:
            snell.synchronize(self.db, b, '192.0.2.1', endpoint_id='second', bind_user='local')
        self.sync6(self.v6(name='First renamed'))
        self.assertEqual(self.local()[1].splitlines()[1], second)

    def test_v6_duplicate_collision_rolls_back(self):
        a, b = self.v6(), self.v6(name='Already exists')
        first, second = snell.uri(a, '192.0.2.1'), snell.uri(b, '192.0.2.1')
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"', (first+'\n'+second,))
        self.db.commit()
        self.sync6(a, bind_user='local')
        before = self.local()
        with self.assertRaises(snell.Error):
            self.sync6(b)
        self.assertEqual(before, self.local())

    def test_uri_obfuscation_name_and_encoding(self):
        value = self.value()
        value['psk'] = 'synthetic+/@=&key'
        p = urlsplit(snell.uri(value, '192.0.2.1'))
        self.assertEqual(unquote(p.username), value['psk'])
        self.assertEqual(unquote(p.fragment), value['name'])
        self.assertEqual(parse_qs(p.query), {'version':['4'],'reuse':['true'],'tfo':['true'],'obfs-mode':['http'],'obfs-host':['yandex.ru']})

    def test_explicit_adoption_preserves_manual_links_tokens_and_group_ids(self):
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.sync(bind_user='local', adopt=True), 1)
        saved = self.local()
        self.assertEqual(saved[2], 6)
        self.assertEqual(saved[4:], ('synthetic-token','untouched-mieru'))
        self.assertEqual(saved[1].splitlines()[1], self.foreign)
        self.assertEqual(self.db.execute('SELECT snell_uri FROM users WHERE id="manual"').fetchone()[0], self.old)
        doc = json.loads(self.db.execute('SELECT document_json FROM user_connection_groups WHERE user_id="local"').fetchone()[0])
        self.assertEqual(doc['profiles'][0]['id'], 'keep-profile-id')
        self.assertEqual(doc['profiles'][0]['name'], 'My alias')
        self.assertEqual(doc['profiles'][0]['uri'], saved[1].splitlines()[0])
        self.assertEqual(self.sync(), 0)
        self.assertEqual(self.sync(bind_user='local', adopt=True), 0)
        self.assertEqual(self.local()[2], 6)

    def test_http_off_and_future_key_port_name_change(self):
        self.sync(bind_user='local', adopt=True)
        new_config = snell.edit_config(self.config.read_bytes(), {'obfs':'off','obfs-host':None,'psk':'new-synthetic-key','listen':'0.0.0.0:19553'})
        self.config.write_bytes(new_config)
        self.tag.write_text('A renamed profile')
        self.assertEqual(self.sync(), 1)
        p = urlsplit(self.local()[1].splitlines()[0])
        self.assertNotIn('obfs-mode', parse_qs(p.query))
        self.assertNotIn('obfs-host', parse_qs(p.query))
        self.assertEqual(p.port,19553)
        self.assertEqual(p.username,'new-synthetic-key')
        self.assertEqual(unquote(p.fragment),'A renamed profile')
        self.assertEqual(self.local()[1].splitlines()[1], self.foreign)

    def test_manual_edit_detaches_and_custom_flags_name_survive(self):
        custom = self.old.replace('reuse=true','reuse=false&custom=value').replace('tfo=true','tfo=false').replace('#Snell-v5','#Personal')
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"', (custom,))
        self.db.commit()
        self.sync(bind_user='local', adopt=True)
        first = self.local()[1]
        p = urlsplit(first)
        self.assertEqual(p.fragment,'Personal')
        self.assertEqual(parse_qs(p.query)['reuse'],['false'])
        self.assertEqual(parse_qs(p.query)['tfo'],['false'])
        self.assertEqual(parse_qs(p.query)['custom'],['value'])
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"', (self.foreign,))
        self.db.commit()
        self.assertEqual(self.sync(),0)
        self.assertEqual(self.local()[1],self.foreign)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM x_manager_snell_links WHERE user_id="local"').fetchone()[0],0)

    def test_new_canonical_binding_without_revision_bump(self):
        canonical = snell.uri(self.value(),'192.0.2.1')
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"',(canonical,))
        self.db.commit()
        self.assertEqual(self.sync(bind_user='local'),0)
        self.assertEqual(self.local()[2],5)

    def test_ambiguous_adoption_rolls_back(self):
        self.db.execute('UPDATE users SET snell_uri=? WHERE id="local"',(self.old+'\n'+self.old.replace('#Snell-v5','#Another'),))
        self.db.commit()
        with self.assertRaises(snell.Error):
            self.sync(bind_user='local',adopt=True)
        self.assertEqual(self.local()[2],5)

    def test_group_collision_rolls_back_without_merging_ids(self):
        doc = self.document
        doc['profiles'].append({'id':'second-id','name':'Other','uri':snell.uri(self.value(),'192.0.2.1')})
        self.db.execute('UPDATE user_connection_groups SET document_json=?',(json.dumps(doc),))
        self.db.commit()
        with self.assertRaises(snell.Error):
            self.sync(bind_user='local',adopt=True)
        self.assertEqual(self.local()[2],5)
        self.assertEqual(self.local()[1].splitlines()[0],self.old)

    def test_port_rules_preserve_order_block_policy_and_other_services(self):
        original = b'-P INPUT ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 19552 -m comment --comment SNELL_FW_BLOCK -j DROP\n-A INPUT -p udp -m udp --dport 19552 -m comment --comment SNELL_MANAGED -j ACCEPT\n'
        with patch.object(snell,'run',return_value=original) as run:
            snell.port_rules(19552,19553)
        calls = run.call_args_list
        self.assertEqual(len(calls),3)
        self.assertEqual(calls[1].args[:6],('iptables','-w','-R','INPUT','2','-p'))
        self.assertIn('DROP',calls[1].args)
        self.assertEqual(calls[2].args[4],'3')
        self.assertIn('19553',calls[2].args)

    def test_transaction_service_failure_restores_config_and_database(self):
        self.sync(bind_user='local',adopt=True)
        before = self.config.read_bytes(), self.local()
        calls = []
        def fail_once():
            calls.append(1)
            if len(calls)==1:
                raise snell.Error('Synthetic service failure')
        with patch.object(snell,'run', return_value=b''):
            with self.assertRaises(snell.Error):
                snell.transaction(self.config,self.tag,self.dbpath,'192.0.2.1',self.root,
                                  {'obfs':'off'},restart_service=fail_once)
        self.assertEqual(len(calls),2)
        self.assertEqual((self.config.read_bytes(),self.local()),before)
        self.assertEqual(len(list(self.root.glob('x-manager-snell-*/subscriptions.db'))),1)

    def test_transaction_success_and_invalid_input(self):
        self.sync(bind_user='local',adopt=True)
        before = self.config.read_bytes()
        with patch.object(snell,'run',return_value=b''):
            count, backup = snell.transaction(self.config,self.tag,self.dbpath,'192.0.2.1',self.root,{'name':'New name'})
        self.assertEqual(count,1)
        self.assertEqual(self.config.read_bytes(),before)
        self.assertEqual(self.tag.read_text(),'New name\n')
        for change in ({'port':443},{'port':8443},{'obfs':'http','obfs_host':'bad\nhost'},{'psk':''}):
            with self.assertRaises(snell.Error):
                snell.transaction(self.config,self.tag,self.dbpath,'192.0.2.1',self.root,change)
        self.assertEqual(self.config.read_bytes(),before)

    def test_actual_shell_generator_uses_shared_uri_and_propagates_failure(self):
        code = (ROOT/'bin/x-manager').read_text()
        start = code.index('extract_current_server_links() {')
        end = code.index('collect_multi_uris() {',start)
        script = code[start:end] + '\nis_snell_installed() { return 0; }\n'
        for name in ('wdtt','mieru','csqtt','dns'):
            script += 'is_'+name+'_installed() { return 1; }\n'
        correct = snell.uri(self.value(),'192.0.2.1')
        script += 'get_snell_uri() { printf "%s" "$FIXTURE_URI"; }\nextract_current_server_links fixture\n'
        import os
        result = subprocess.run(['bash','-c',script],env=dict(os.environ,FIXTURE_URI=correct),capture_output=True,text=True)
        self.assertEqual(result.returncode,0)
        self.assertEqual(json.loads(result.stdout)['snell_uri'],correct)
        script = script.replace('printf "%s" "$FIXTURE_URI"','return 1')
        failed = subprocess.run(['bash','-c',script],capture_output=True,text=True)
        self.assertNotEqual(failed.returncode,0)
        self.assertEqual(failed.stdout,'')


if __name__ == '__main__':
    unittest.main()
