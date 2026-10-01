import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit, unquote

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mieru', ROOT/'scripts/mieru-subscriptions.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def payload(mode=1, rotation=7):
    varint = bytes([rotation]) if rotation < 128 else bytes([(rotation & 127) | 128, rotation >> 7])
    body = bytes([8, mode, 16]) + varint
    return base64.b64encode(bytes([50, len(body)]) + body).decode()


def model(mode=1, rotation=7):
    encoded = payload(mode, rotation)
    original = m.decode(encoded)  # Use the shipped Mita codec, not a test decoder.
    return dict(config=dict(users=[dict(name='qa user', password='synthetic:+&@')],
                            portBindings=[dict(portRange='2020-2030', protocol='TCP')],
                            trafficPattern=original), original=original, payload=encoded,
                entropy=m.entropy(original))


class MieruSubscriptions(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = model()
        self.good = m.export(self.model, '192.0.2.1', 'qa user', 'Keep name')['uri']
        self.bad = self.good.replace('LOW_ENTROPY_MODE_32', 'LOW_ENTROPY_MODE_48')
        self.db = self.root/'db.sqlite'
        with sqlite3.connect(self.db) as db:
            db.execute('CREATE TABLE users(id TEXT PRIMARY KEY,mieru_uri TEXT,revision INTEGER,updated_at TEXT,token TEXT,snell_uri TEXT)')
            db.execute('CREATE TABLE user_connection_groups(user_id TEXT,document_json TEXT)')
            db.execute('INSERT INTO users VALUES(?,?,5,?,?,?)', ('local', self.bad+'\nmanual-external\n', 'old-date','keep-token','keep-snell'))
            db.execute('INSERT INTO users VALUES(?,?,2,?,?,?)', ('other',self.bad,'old-date','other-token','other-snell'))
            self.doc = dict(profiles=[dict(id='keep-id',name='alias',uri=self.bad)],groups=[dict(id='group',memberIds=['keep-id'])])
            db.execute('INSERT INTO user_connection_groups VALUES(?,?)',('local',json.dumps(self.doc)))
        self.request = dict(user_id='local',revision=5,uri_sha256=hashlib.sha256(self.bad.encode()).hexdigest())

    def row(self, user='local'):
        with sqlite3.connect(self.db) as db:
            return db.execute('SELECT * FROM users WHERE id=?',(user,)).fetchone()

    def test_native_codec_roundtrip_modes_rotations_and_encoding(self):
        for mode in (1,3):
            for rot in (0,7,224):
                value=model(mode,rot)
                uri=m.export(value,'192.0.2.1','qa user','Name + & /')['uri']
                q=m.validate(uri)
                self.assertEqual(m.decode(q['traffic-pattern']),value['original'])
                self.assertEqual(q['low-entropy-mode'],value['original']['lowEntropy']['mode'])
                self.assertEqual(q['low-entropy-mask-rotation'],value['original']['lowEntropy']['maskRotation'])
                self.assertEqual(unquote(urlsplit(uri).password),'synthetic:+&@')
                self.assertEqual(q['profile'],'Name + & /')
                self.assertEqual(m.repaired(uri,value,'192.0.2.1'),uri)

    def test_contradiction_and_malformed_payload_are_rejected(self):
        with self.assertRaises(m.Error):m.validate(self.bad)
        with self.assertRaises(m.Error):m.decode('not-a-protobuf')
        with self.assertRaises(m.Error):m.validate(self.good+'&low-entropy-mode=LOW_ENTROPY_MODE_48')
        wrong=self.good.replace('ROTATE_RIGHT_7','ROTATE_LEFT_7')
        with self.assertRaises(m.Error):m.validate(wrong)

    def test_payload_only_and_query_only_representations(self):
        p,q=m.parse(self.good)
        simple='&'.join(x for x in p.query.split('&') if not x.startswith('low-entropy-'))
        m.validate(p._replace(query=simple).geturl())
        simple='&'.join(x for x in p.query.split('&') if not x.startswith('traffic-pattern='))
        m.validate(p._replace(query=simple).geturl())

    def test_rpc_snapshot_detects_race_and_uses_effective_enums(self):
        def rpc(*args):
            if args==('describe','config'):return json.dumps(self.model['config'])
            if args==('export','traffic-pattern'):return self.model['payload']
            return json.dumps(self.model['original'])
        with patch.object(m,'mita',side_effect=rpc):
            self.assertEqual(m.snapshot(),self.model)
        outputs=[json.dumps(self.model['config']),self.model['payload'],json.dumps(self.model['original']),
                 json.dumps(self.model['original']),json.dumps({})]
        with patch.object(m,'mita',side_effect=outputs):
            with self.assertRaises(m.Error):m.snapshot()

    def test_preview_no_write_and_explicit_repair_preserves_other_data(self):
        before=self.db.read_bytes()
        result=m.repair(self.db,self.request,self.model,'192.0.2.1')
        self.assertTrue(result['changed']);self.assertFalse(result['applied'])
        self.assertEqual(self.db.read_bytes(),before)
        other=self.row('other')
        result=m.repair(self.db,self.request,self.model,'192.0.2.1',True,self.root)
        self.assertEqual(self.row()[1],self.good+'\nmanual-external\n')
        self.assertEqual(self.row()[2],6)
        self.assertEqual(self.row()[4:],('keep-token','keep-snell'))
        self.assertEqual(self.row('other'),other)
        with sqlite3.connect(self.db) as db:
            doc=json.loads(db.execute('SELECT document_json FROM user_connection_groups').fetchone()[0])
        expected=copy.deepcopy(self.doc);expected['profiles'][0]['uri']=self.good
        self.assertEqual(doc,expected)
        with sqlite3.connect(Path(result['backup'])/'subscriptions.db') as db:
            self.assertEqual(db.execute('SELECT revision FROM users WHERE id="local"').fetchone()[0],5)
        again=dict(self.request,revision=6,uri_sha256=hashlib.sha256(self.good.encode()).hexdigest())
        self.assertFalse(m.repair(self.db,again,self.model,'192.0.2.1',True,self.root)['changed'])

    def test_revision_credentials_pattern_or_fingerprint_mismatch_never_writes(self):
        before=self.db.read_bytes()
        for key,value in [('revision',6),('uri_sha256','0'*64),('user_id','missing')]:
            with self.assertRaises(m.Error):m.repair(self.db,dict(self.request,**{key:value}),self.model,'192.0.2.1',True,self.root)
        with self.assertRaises(m.Error):m.repair(self.db,self.request,model(3),'192.0.2.1',True,self.root)
        with self.assertRaises(m.Error):m.repair(self.db,self.request,self.model,'192.0.2.2',True,self.root)
        self.assertEqual(self.db.read_bytes(),before)

    def test_group_collision_rolls_back(self):
        doc=copy.deepcopy(self.doc);doc['profiles'].append(dict(id='second',name='keep',uri=self.good))
        with sqlite3.connect(self.db) as db:db.execute('UPDATE user_connection_groups SET document_json=?',(json.dumps(doc),))
        before=self.row()
        with self.assertRaises(m.Error):m.repair(self.db,self.request,self.model,'192.0.2.1',True,self.root)
        self.assertEqual(self.row(),before)

    def test_targeted_restore_preserves_other_users_and_rejects_stale_rollback(self):
        result=m.repair(self.db,self.request,self.model,'192.0.2.1',True,self.root)
        with sqlite3.connect(self.db) as db:db.execute('UPDATE users SET token="new-unrelated-token" WHERE id="other"')
        other=self.row('other')
        restored=m.restore(self.db,Path(result['backup']))
        self.assertEqual(restored['revision'],7)
        self.assertEqual(self.row()[1],self.bad+'\nmanual-external\n')
        self.assertEqual(self.row('other'),other)
        with self.assertRaises(m.Error):m.restore(self.db,Path(result['backup']))

    def test_both_real_shell_paths_use_shared_export_and_propagate_errors(self):
        source=(ROOT/'bin/x-manager').read_text()
        functions=[]
        for name in ('mieru_export_links','extract_current_server_links'):
            functions.append(re.search(r'^'+name+r'\(\) \{\n.*?(?=^[A-Za-z_]\w*\(\) \{|\Z)',source,re.M|re.S)[0])
        store=self.root/'users.json';store.write_text(json.dumps({'qa user':'synthetic'}))
        exported=m.export(self.model,'192.0.2.1','qa user','Keep name')
        output=self.root/'output';output.write_text(json.dumps(exported))
        setup='''
show_mieru_header() { :; }; get_mieru_tag() { echo 'Keep name'; }; get_mieru_routing() { echo direct; }
is_snell_installed() { return 1; }; is_wdtt_installed() { return 1; }; is_csqtt_installed() { return 1; }; is_dns_installed() { return 1; }; is_mieru_installed() { return 0; }
qrencode() { :; }
mieru_tool() { [ "$TEST_FAIL" = 0 ] || return 41; if [[ "$*" == *--json* ]]; then cat "$TEST_OUTPUT"; else jq -r .uri "$TEST_OUTPUT"; fi; }
SERVER_IP=192.0.2.1
MIERU_USER_STORE="$TEST_STORE"
'''
        for target in ('mieru_export_links','extract_current_server_links'):
            for fail in ('0','1'):
                result=subprocess.run(['bash','-c','\n'.join(functions)+setup+'\n'+target],input='1\n\n',text=True,capture_output=True,
                  env=dict(os.environ,TEST_STORE=str(store),TEST_OUTPUT=str(output),TEST_FAIL=fail),timeout=5)
                if fail=='1':self.assertNotEqual(result.returncode,0)
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertIn('LOW_ENTROPY_MODE_32',result.stdout)
                    self.assertNotIn('LOW_ENTROPY_MODE_48',result.stdout)


if __name__=='__main__':unittest.main()
