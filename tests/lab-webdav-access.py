"""Run in a disposable Debian mount AND network namespace, never a VPS."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time

assert Path('/.x-manager-test-lab').is_file()
assert os.environ.get('XM_PARENT_NET') and os.readlink('/proc/self/ns/net') != os.environ['XM_PARENT_NET'], 'Private network required'
spec=importlib.util.spec_from_file_location('access',Path(__file__).resolve().parents[1]/'scripts/webdav-access.py')
a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
def run(*args): return subprocess.check_output(args,text=True).strip()
client=subprocess.Popen(['unshare','--net','sleep','120'])
sockets=[]
try:
    for _ in range(100):
        if os.readlink('/proc/%d/ns/net'%client.pid) != os.readlink('/proc/self/ns/net'): break
        time.sleep(.01)
    def peer(*args): return run('nsenter','-t',str(client.pid),'-n',*args)
    run('ip','link','set','lo','up')
    run('ip','link','add','wdserver','type','veth','peer','name','wdclient')
    run('ip','link','set','wdclient','netns',str(client.pid))
    run('ip','addr','add','192.0.2.1/30','dev','wdserver')
    run('ip','-6','addr','add','fd42::1/64','dev','wdserver','nodad')
    run('ip','link','set','wdserver','up')
    peer('ip','addr','add','192.0.2.2/30','dev','wdclient')
    peer('ip','-6','addr','add','fd42::2/64','dev','wdclient','nodad')
    peer('ip','link','set','wdclient','up')
    for family,host in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
        for port in (28080,28081):
            s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6: s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            s.bind((host,port));s.listen(100);sockets.append(s)
    probe='import socket,sys; s=socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET); s.settimeout(.35); ok=s.connect_ex((sys.argv[1],int(sys.argv[2])))==0; s.close(); print(int(ok))'
    def check(opened,port=28080):
        for host in ('192.0.2.1','fd42::1'):
            assert peer('python3','-c',probe,host,str(port))==str(int(opened)),(host,opened)
        assert run('python3','-c',probe,'127.0.0.1',str(port))=='1'
        assert run('python3','-c',probe,'::1',str(port))=='1'
    for family in a.Firewall.families:
        run(family,'-A','INPUT','-p','tcp','--dport','28081','-m','comment','--comment','UNRELATED_FIXTURE','-j','ACCEPT')
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        (root/'config.env').write_text('WEBDAV_MODE=selfhosted\nWEBDAV_LISTEN=:28080')
        check(True)
        a.change('blocked',root);check(False)
        before={f:run(f+'-save') for f in a.Firewall.families}
        a.change('blocked',root)
        assert before=={f:run(f+'-save') for f in a.Firewall.families}
        a.change('open',root);check(True)
        class FailIPv6(a.Firewall):
            failed=False
            def apply(self,family,old,new,test=False):
                if family=='ip6tables' and not test and not self.failed:
                    self.failed=True
                    raise RuntimeError('Injected IPv6 commit failure')
                return super().apply(family,old,new,test)
        try: a.change('blocked',root,FailIPv6())
        except RuntimeError: pass
        else: raise AssertionError('Failure expected')
        check(True)
        assert a.read_policy(root)=='open'
        a.change('blocked',root)
        (root/'config.env').write_text('WEBDAV_MODE=multi\nSELFHOSTED_PORT=28081')
        a.change('sync',root);check(False,28081);check(True,28080)
        (root/'config.env').write_text('WEBDAV_MODE=multi\nMULTI_LOCAL_ENABLED=false')
        a.change('sync',root);check(True,28081)
        for family in a.Firewall.families:
            assert 'UNRELATED_FIXTURE' in run(family+'-save')
    print('PASS real IPv4/IPv6 TCP: block/open, loopback, repeat, changed port, Multi/cloud, partial failure rollback, unrelated rules preserved')
finally:
    for s in sockets: s.close()
    client.terminate();client.wait(timeout=5)
