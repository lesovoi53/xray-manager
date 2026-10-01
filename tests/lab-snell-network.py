"""Run with unshare -n, root; no host or VPS network changes.
Usage: unshare -n python3 tests/lab-snell-network.py /path/to/xray
"""
import importlib.util,json,multiprocessing,os,socket,struct,subprocess,sys,tempfile,threading,time
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'A private network namespace is required'
spec=importlib.util.spec_from_file_location('routing',ROOT/'scripts/snell-routing.py')
routing=importlib.util.module_from_spec(spec);spec.loader.exec_module(routing)
spec=importlib.util.spec_from_file_location('installer',ROOT/'scripts/installer-state.py')
installer=importlib.util.module_from_spec(spec);spec.loader.exec_module(installer)
def run(*a):return routing.run(*a)
run('ip','link','set','lo','up')
for address in ['198.18.0.1/32']:
 run('ip','addr','add',address,'dev','lo')
port=12346;udp_port=12345;uid=43210
root=Path(tempfile.mkdtemp(prefix='snell-net-'))
cfg={'log':{'loglevel':'debug'},'inbounds':[
 {'tag':'redirect','listen':'127.0.0.1','port':port,'protocol':'dokodemo-door','settings':{'network':'tcp,udp','followRedirect':True}},
 {'tag':'tproxy','listen':'127.0.0.1','port':udp_port,'protocol':'dokodemo-door','settings':{'network':'tcp,udp','followRedirect':True},'streamSettings':{'sockopt':{'tproxy':'tproxy'}}}],
 'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'blocked','protocol':'blackhole'}],
 'routing':{'rules':[{'type':'field','ip':['127.0.0.0/8'],'outboundTag':'blocked'}]}}
(root/'config.json').write_text(json.dumps(cfg))
log=(root/'xray.log').open('w')
xray=subprocess.Popen([sys.argv[1],'run','-c',str(root/'config.json')],stdout=log,stderr=subprocess.STDOUT)
def answer(data):
 qtype=struct.unpack('!H',data[-4:-2])[0]
 result=socket.inet_pton(socket.AF_INET6,'2001:db8::1') if qtype==28 else socket.inet_aton('198.51.100.7')
 return data[:2]+b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'+data[12:]+b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,60,len(result))+result
def dns_udp(udp):
 while True:
  try:data,peer=udp.recvfrom(4096);udp.sendto(answer(data),peer)
  except OSError:return
def dns_tcp(tcp):
 while True:
  try:
   c,_=tcp.accept()
   with c:
    length=struct.unpack('!H',c.recv(2))[0];data=c.recv(length);reply=answer(data);c.sendall(struct.pack('!H',len(reply))+reply)
  except OSError:return
def resolver(pipe):
 os.unshare(os.CLONE_NEWNET)
 pipe.send(os.getpid());pipe.recv()
 run('ip','link','set','lo','up')
 run('ip','addr','add','192.0.2.53/24','dev','dnspeer')
 run('ip','link','set','dnspeer','up')
 run('ip','route','add','198.18.0.1/32','via','192.0.2.1')
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('192.0.2.53',53))
 tcp=socket.socket();tcp.bind(('192.0.2.53',53));tcp.listen()
 threading.Thread(target=dns_tcp,args=(tcp,),daemon=True).start()
 pipe.send('ready');dns_udp(udp)
parent,child=multiprocessing.Pipe()
dns=multiprocessing.get_context('fork').Process(target=resolver,args=(child,));dns.start()
dns_pid=parent.recv()
run('ip','link','add','dnswan','type','veth','peer','name','dnspeer')
run('ip','link','set','dnspeer','netns',str(dns_pid))
run('ip','addr','add','192.0.2.1/24','dev','dnswan')
run('ip','link','set','dnswan','up')
parent.send('go');assert parent.recv()=='ready'
probe='''import os,socket,struct,sys
os.setuid(43210)
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if sys.argv[1]=='tcp' else socket.SOCK_DGRAM)
s.settimeout(1);s.bind(('198.18.0.1',0));s.connect(('192.0.2.53',53))
for n in range(3):
 d=struct.pack('!HHHHHH',43000+n,256,1,0,0,0)+b'\\x02qa\\x07invalid\\x00'+struct.pack('!HH',int(sys.argv[2]),1)
 s.sendall(struct.pack('!H',len(d))+d if sys.argv[1]=='tcp' else d)
 if sys.argv[1]=='tcp': size=struct.unpack('!H',s.recv(2))[0];r=s.recv(size)
 else:r=s.recv(4096)
 assert r[:2]==d[:2] and r[3]&15==0
 if sys.argv[1]=='tcp': break
'''
def probe_ok(protocol='udp',qtype=1):
 p=subprocess.run(['python3','-c',probe,protocol,str(qtype)],capture_output=True)
 return p.returncode==0
try:
 time.sleep(.3)
 routing.verify_gateways([cfg],port,udp_port,uid)
 # Exact old defect: UDP REDIRECT to a listening TCP+UDP Xray gateway.
 run('iptables','-t','nat','-N','SNELL_OUT')
 run('iptables','-t','nat','-A','SNELL_OUT','-p','udp','-j','REDIRECT','--to-ports',str(port))
 run('iptables','-t','nat','-A','OUTPUT','-m','owner','--uid-owner',str(uid),'-j','SNELL_OUT')
 assert not probe_ok(),'Legacy UDP REDIRECT unexpectedly passed'
 text=(root/'xray.log').read_text()
 assert '127.0.0.1:12346' in text and 'blocked' in text,'No original-destination evidence'
 print('REPRODUCED: UDP REDIRECT loses original destination; Xray routes loopback to blocked',flush=True)
 state=root/'state.json'
 routing.apply('xray',uid,1488,['198.18.0.1'],port,udp_port,state,root)
 for proto in ['udp','tcp']:
  for qtype in [1,28]:assert probe_ok(proto,qtype),(proto,qtype)
 print('PASS UDP/TCP DNS A/AAAA, including repeated UDP on one socket',flush=True)
 first=run('iptables','-t','mangle','-S')
 routing.apply('xray',uid,1488,['198.18.0.1'],port,udp_port,state,root)
 assert run('iptables','-t','mangle','-S')==first
 assert probe_ok()
 # Exercise installer policy rollback against the real kernel in both directions.
 def policy():
  return dict(rules=[r for r in json.loads(run('ip','-j','-4','rule','show')) if r.get('priority')==1988],
              routes=[r for r in json.loads(run('ip','-j','-4','route','show','table','all')) if str(r.get('table'))=='1988'],owned=True)
 active=policy();empty=dict(rules=[],routes=[],owned=False)
 installer.restore_snell_policy(empty,active)
 assert not policy()['rules'] and not policy()['routes']
 installer.restore_snell_policy(active,policy())
 assert policy()==active and probe_ok()
 print('PASS installer policy rollback restores/removes only Snell table/rule',flush=True)
 routing.apply('direct',uid,1488,['198.18.0.1'],port,udp_port,state,root)
 assert probe_ok() and not state.exists()
 assert 'SNELL' not in run('iptables','-t','mangle','-S')
 assert '1988' not in run('ip','-4','rule','show')
 print('PASS repeat without duplicates and direct/xray cleanup',flush=True)
 # Failure after mangle commit must restore tables and remove policy resources.
 original_run=routing.run
 def fail_nat(*args,**kwargs):
  if args[0]=='iptables-restore' and '--noflush' in args and '--test' not in args and kwargs.get('data','').startswith('*nat'):
   raise routing.Error('Synthetic kernel commit failure')
  return original_run(*args,**kwargs)
 with patch.object(routing,'run',side_effect=fail_nat):
  try:routing.apply('xray',uid,1488,['198.18.0.1'],port,udp_port,state,root)
  except routing.Error:pass
  else:raise AssertionError('Failure was hidden')
 assert 'SNELL' not in run('iptables','-t','mangle','-S')
 assert '1988' not in run('ip','-4','rule','show') and not state.exists()
 assert probe_ok()
 # Occupied policy slot is rejected before touching any rules.
 run('ip','-4','rule','add','priority','1988','lookup','main')
 snapshot=run('iptables','-t','nat','-S')
 try:routing.apply('xray',uid,1488,['198.18.0.1'],port,udp_port,state,root)
 except routing.Error:pass
 else:raise AssertionError('Foreign policy rule was overwritten')
 assert run('iptables','-t','nat','-S')==snapshot
 run('ip','-4','rule','del','priority','1988','lookup','main')
 print('PASS partial-commit rollback and foreign-rule collision preflight',flush=True)
except Exception:
 print('LAB-ONLY XRAY TRACE:',(root/'xray.log').read_text()[-7000:],flush=True)
 print('LAB-ONLY MANGLE:',run('iptables','-t','mangle','-L','-n','-v'),flush=True)
 raise
finally:
 xray.terminate();xray.wait(timeout=5);log.close();dns.terminate();dns.join(timeout=5)
 import shutil
 shutil.rmtree(root)
