"""Real standalone core, custom loopback gateways and SOCKS HTTP round-trip."""
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

assert Path('/.x-manager-test-lab').is_file(), 'Disposable lab only'
ROOT = Path('/work/x-manager')
spec = importlib.util.spec_from_file_location('discovery', ROOT/'scripts/xray-discovery.py')
discovery = importlib.util.module_from_spec(spec); spec.loader.exec_module(discovery)


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'XRAY_STANDALONE_OK')
    def log_message(self, *args):
        pass


origin = http.server.ThreadingHTTPServer(('127.0.0.1',0), Origin)
threading.Thread(target=origin.serve_forever,daemon=True).start()
held = [socket.socket() for _ in range(3)]
for sock in held:
    sock.bind(('127.0.0.1',0))
numbers = [sock.getsockname()[1] for sock in held]
for sock in held: sock.close()
assert not set(numbers) & {443,8443,10808,12345,12346}
inbounds = [dict(tag='socks-fixture',listen='127.0.0.1',port=numbers[0],protocol='socks',settings={'auth':'noauth','udp':True})]
for index, mode in ((1,'redirect'),(2,'tproxy')):
    inbounds.append(dict(tag=mode+'-fixture',listen='127.0.0.1',port=numbers[index],protocol='dokodemo-door',
                         settings={'network':'tcp,udp','followRedirect':True},streamSettings={'sockopt':{'tproxy':mode}}))
with tempfile.TemporaryDirectory() as tmp:
    config = Path(tmp)/'config.json'
    config.write_text(json.dumps(dict(log={'loglevel':'none'},inbounds=inbounds,outbounds=[{'protocol':'freedom','tag':'direct'}])))
    before = config.read_bytes()
    with open(Path(tmp)/'core.log','w') as log:
        subprocess.run(['/opt/xray-test','run','-test','-config',str(config)],check=True,stdout=log,stderr=log)
        core = subprocess.Popen(['/opt/xray-test','run','-config',str(config)],stdout=log,stderr=log)
        try:
            values = discovery.discover([config])
            assert [values[k] for k in discovery.KEYS] == numbers
            for attempt in range(30):
                try: discovery.verify(values); break
                except OSError: time.sleep(.1)
            else: raise AssertionError('Standalone gateways did not start')
            with socket.create_connection(('127.0.0.1',numbers[0]),timeout=5) as sock:
                sock.sendall(b'\x05\x01\x00'); assert sock.recv(2) == b'\x05\x00'
                sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',origin.server_port))
                response = sock.recv(10); assert response[1] == 0
                sock.sendall(b'GET / HTTP/1.0\r\nHost: fixture\r\n\r\n')
                response = b''
                while True:
                    data = sock.recv(4096)
                    if not data: break
                    response += data
                assert b'XRAY_STANDALONE_OK' in response
            assert config.read_bytes() == before
            print('PASS: standalone Xray config validation, discovery of 3 nonstandard gateways, SOCKS5 HTTP 200, config unchanged')
            print('Core:',subprocess.check_output(['/opt/xray-test','version'],text=True).splitlines()[0])
        finally:
            core.terminate(); core.wait(timeout=10)
origin.shutdown(); origin.server_close()
