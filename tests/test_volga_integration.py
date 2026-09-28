import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tuna-sub-server'))
import importlib
sub=importlib.import_module('tuna-subscriptions')
spec=importlib.util.spec_from_file_location('volga_helper',ROOT/'scripts/openflux-volga.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)

class VolgaIntegration(unittest.TestCase):
    def test_wdtt_uses_only_saved_password(self):
        source=(ROOT/'bin/x-manager').read_text()
        fn=re.search(r'^get_wdtt_password\(\) \{.*?^\}',source,re.M|re.S).group()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'password'
            command=fn+'\nget_wdtt_password'
            env=dict(os.environ,WDTT_PASSWORD_FILE=str(path))
            missing=subprocess.run(['bash','-c',command],capture_output=True,text=True,env=env)
            self.assertNotEqual(missing.returncode,0)
            self.assertEqual(missing.stdout,'')
            path.write_text('synthetic-password\n')
            saved=subprocess.run(['bash','-c',command],capture_output=True,text=True,env=env)
            self.assertEqual(saved.returncode,0)
            self.assertEqual(saved.stdout.strip(),'synthetic-password')

    def test_export_summary_reads_payload(self):
        source=(ROOT/'bin/x-manager').read_text()
        fn=re.search(r'^export_user_openflux_sub\(\) \{.*?^\}',source,re.M|re.S).group()
        body={'uri':'openflux-bundle://v2/fixture','enabled':True,'revision':14,'payload':{'name':'fixture germany','mode':'multistream','balancer_strategy':'leastPing','revision':14,'groups':[{'urls':['https://disk.yandex.ru/i/'+str(i) for i in range(4)]}]}}
        script=fn+'\nclear() { :; }; curl() { printf "%s\\n200" "$RESPONSE"; }; export_user_openflux_sub fixture fixture'
        run=subprocess.run(['bash','-c',script],input='n\n\n',text=True,capture_output=True,env=dict(os.environ,RESPONSE=json.dumps(body)))
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertRegex(run.stdout,r'Имя бандла:\s+fixture germany')
        self.assertRegex(run.stdout,r'Режим:\s+multistream.*leastPing')
        self.assertRegex(run.stdout,r'Групп:\s+1.*Всего URL:\s+4.*Ревизия: 14')
        self.assertIn(body['uri'],run.stdout)

    def test_session_cookie_zero_and_empty_expiry_survive_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'cookies.txt'
            path.write_text('# Netscape HTTP Cookie File\n.yandex.ru\tTRUE\t/\tTRUE\t0\tzero\tfixture\n.yandex.ru\tTRUE\t/\tTRUE\t\tempty\tfixture\n')
            jar=helper.load_jar(path)
            self.assertEqual({c.name for c in jar},{'zero','empty'})
            self.assertTrue(all(c.expires is None for c in jar))

    def test_menu_detection(self):
        source=(ROOT/'bin/x-manager').read_text()
        fn=re.search(r'^detect_transport_from_url\(\) \{.*?^\}',source,re.M|re.S).group()
        out=subprocess.check_output(['bash','-c',fn+'\ndetect_transport_from_url https://disk.yandex.ru/i/test'],text=True)
        self.assertEqual(out.strip(),'vyandex')

    def test_validate_rejects_wrong_host_duplicates_and_shell(self):
        for val in ['https://disk.yandex.ru.evil.test/i/doc','https://u@disk.yandex.ru/i/doc','http://disk.yandex.ru/i/doc','https://disk.yandex.ru/i/$(id)','https://disk.yandex.ru/i/a,https://disk.yandex.ru/i/a']:
            with self.subTest(val=val),self.assertRaises(ValueError):helper.validate(val)
        self.assertEqual(helper.validate('https://disk.yandex.ru/i/a?x=1&y=2'),'https://disk.yandex.ru/i/a?x=1&y=2')

    def test_import_serialize_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);inst=root/'instances';inst.mkdir();mode=root/'mode';mode.write_text('multistream')
            urls=['https://disk.yandex.ru/i/'+str(i) for i in range(4)]
            (inst/'3.env').write_text('TRANSPORT="vyandex"\nCODEC="batched"\nENCRYPTION_KEY="synthetic-key-123456"\nURL="'+','.join(urls)+'"\n')
            app=sub.SubscriptionApp({'database':{'path':str(root/'db')},'server':{'bind_address':'127.0.0.1','port':0},'logging':{'file':str(root/'log'),'level':'ERROR'},'limits':{'max_nickname_length':64,'max_uri_length':4096,'max_users':1000}})
            try:
                status,result=app.import_local_openflux_groups(str(inst),str(mode));self.assertEqual(status,200)
                self.assertEqual(result['imported_count'],1)
                rows=[tuple(r) for r in app.conn.execute('SELECT * FROM openflux_groups')]
                app.import_local_openflux_groups(str(inst),str(mode))
                self.assertEqual(rows,[tuple(r) for r in app.conn.execute('SELECT * FROM openflux_groups')])
                g=dict(app.conn.execute('SELECT * FROM openflux_groups').fetchone())
                payload={'schema':sub.OPENFLUX_SCHEMA_V2,'version':2,'issuer_id':app.issuer_id,'id':'22222222-2222-4222-8222-222222222222','revision':1,'name':'Volga','mode':'multistream','balancer_strategy':'roundRobin','groups':[{'id':g['id'],'name':g['name'],'transport':'vyandex','urls':urls,'codec':'batched','encryption_key':'synthetic-key-123456'}]}
                ok,err,uri=sub.serialize_openflux_v2_bundle(payload)
                self.assertTrue(ok,err)
                ok,err,decoded=sub.deserialize_openflux_v2_bundle(uri)
                self.assertTrue(ok,err);self.assertEqual(decoded,payload)
            finally:app.conn.close()

    def test_runner_socks_and_private_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);etc=root/'etc';etc.mkdir();(etc/'openflux').mkdir();(etc/'x-manager').mkdir()
            (etc/'openflux/routing.mode').write_text('xray')
            (etc/'x-manager/gateways.env').write_text('XRAY_SOCKS_PORT=10808\n')
            env=root/'channel.env';env.write_text('TRANSPORT=vyandex\nURL=https://disk.yandex.ru/i/test\nCODEC=batched\nDEBUG=0\n')
            binary=root/'openflux';binary.write_text('#!/usr/bin/env python3\nimport json,sys\nfrom pathlib import Path\na=sys.argv[1:];p=next(x.split("=",1)[1] for x in a if x.startswith("--url-file="));assert Path(p).read_text()=="https://disk.yandex.ru/i/test";print(json.dumps(a))\n');binary.chmod(0o755)
            runner=(ROOT/'scripts/openflux-runner.sh').read_text().replace('/etc/',str(etc)+'/').replace('/usr/local/bin/openflux',str(binary)).replace('/usr/local/share/x-manager/scripts/openflux-volga.py',shlex.quote(str(ROOT/'scripts/openflux-volga.py')))
            run=subprocess.run(['bash','-c',runner,'runner',str(env)],capture_output=True,text=True)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertIn('--upstream-socks5=127.0.0.1:10808',run.stdout)
            self.assertNotIn('https://disk',run.stdout)
            (etc/'x-manager/gateways.env').unlink()
            run=subprocess.run(['bash','-c',runner,'runner',str(env)],capture_output=True,text=True)
            self.assertNotEqual(run.returncode,0);self.assertIn('gateway configuration missing',run.stderr)

if __name__=='__main__':unittest.main()
