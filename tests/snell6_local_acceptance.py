"""Bounded loopback-only qualification; no production configs, SSH or external DNS.

Requires an explicit sing-box-extended executable and either Python cryptography
or --tls-fixture pointing to a disposable local test certificate and key.
Both server and client use that executable; this is not Debian/Android acceptance.
"""
import argparse
import contextlib
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlencode

BODY = b"Snell6-local-content-" * 4096
PSK = "synthetic-local-only-0123456789abcdef"


def read(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            raise EOFError("short response")
        data += chunk
    return data


def address(host, port):
    try:
        result = b"\x01" + socket.inet_aton(host)
    except OSError:
        raw = host.encode("ascii")
        result = b"\x03" + bytes([len(raw)]) + raw
    return result + struct.pack("!H", port)


def decode_address(s, kind):
    if kind == 1:
        host = socket.inet_ntoa(read(s, 4))
    elif kind == 3:
        host = read(s, read(s, 1)[0]).decode()
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, read(s, 16))
    else:
        raise ValueError("invalid SOCKS address")
    return host, struct.unpack("!H", read(s, 2))[0]


def socks(port, host="0.0.0.0", target=0, command=1):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    try:
        s.settimeout(3)
        s.sendall(b"\x05\x01\x00")
        assert read(s, 2) == b"\x05\x00"
        s.sendall(bytes([5, command, 0]) + address(host, target))
        h = read(s, 4)
        assert h[:3] == b"\x05\x00\x00", "SOCKS rejected request"
        peer = decode_address(s, h[3])
        return s, peer
    except BaseException:
        s.close()
        raise


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


def certificate(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "snell.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("snell.test"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    certpath, keypath = root / "cert.pem", root / "key.pem"
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return certpath, keypath


@contextlib.contextmanager
def process(core, root, name, config, logs, xray=False):
    cfg = root / (name + ".json")
    cfg.write_text(json.dumps(config), encoding="utf-8")
    with (logs / (name + ".log")).open("wb") as log:
        check = [str(core), "run", "-test", "-config", str(cfg)] if xray else [str(core), "check", "-c", str(cfg)]
        subprocess.run(check, stdout=log, stderr=log,
                       check=True, timeout=15)
        p = subprocess.Popen([str(core), "run", "-c", str(cfg)], stdout=log, stderr=log,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            time.sleep(.4)
            assert p.poll() is None, "core exited during startup"
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(5)


def https(socks_port, target_port, host, tls):
    conn, _ = socks(socks_port, host, target_port)
    with conn, tls.wrap_socket(conn, server_hostname=host) as secured:
        secured.sendall(b"GET / HTTP/1.0\r\nHost: snell.test\r\n\r\n")
        data = b""
        while True:
            chunk = secured.recv(65536)
            if not chunk:
                break
            data += chunk
    header, body = data.split(b"\r\n\r\n", 1)
    assert b" 200 " in header and body == BODY, "HTTPS content mismatch"


def udp(socks_port, target, payload):
    control, peer = socks(socks_port, command=3)
    with control, socket.socket(type=socket.SOCK_DGRAM) as s:
        s.settimeout(3)
        s.sendto(b"\0\0\0" + address("127.0.0.1", target) + payload, peer)
        packet = s.recv(65535)
        assert packet[:4] == b"\0\0\0\x01", "unexpected UDP envelope"
        assert socket.inet_ntoa(packet[4:8]) == "127.0.0.1"
        assert struct.unpack("!H", packet[8:10])[0] == target
        return packet[10:]


def run(core, out, tls_fixture=None, xray=None):
    rows = []
    out.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    version = subprocess.check_output([str(core), "version"], text=True, timeout=10)
    summary = {"core_sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
               "core_version": version, "core_path": str(core), "scope": "loopback same-core server/client",
               "external_network": False, "cases": rows}
    if xray:
        summary.update(scope="Snell v6 -> SOCKS5 Xray -> loopback fixtures",
                       xray_sha256=hashlib.sha256(xray.read_bytes()).hexdigest(),
                       xray_version=subprocess.check_output([str(xray), "version"], text=True, timeout=10))
    with tempfile.TemporaryDirectory(prefix="snell6-local-") as tmp:
        root = Path(tmp)
        cert, key = ((tls_fixture / "cert.pem", tls_fixture / "key.pem")
                     if tls_fixture else certificate(root))
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.load_cert_chain(cert, key)
        client_tls = ssl.create_default_context(cafile=str(cert))
        web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        web.socket = server_tls.wrap_socket(web.socket, server_side=True)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        fixture = socket.socket(type=socket.SOCK_DGRAM)
        fixture.bind(("127.0.0.1", 0))
        fixture.settimeout(.2)
        stop = threading.Event()

        def responder():
            while not stop.is_set():
                try:
                    packet, peer = fixture.recvfrom(65535)
                    if packet[:2] == b"\x00\x01" and packet[4:8] == bytes.fromhex("2112a442"):
                        mapped = (b"\x00\x01" + struct.pack("!H", peer[1] ^ 0x2112)
                                  + bytes(a ^ b for a, b in zip(socket.inet_aton(peer[0]), packet[4:8])))
                        answer = b"\x01\x01\x00\x0c" + packet[4:20] + b"\x00\x20\x00\x08" + mapped
                    elif packet[:2] == b"\x12\x34":
                        qtype = struct.unpack("!H", packet[-4:-2])[0]
                        value = socket.inet_aton("192.0.2.7") if qtype == 1 else socket.inet_pton(socket.AF_INET6, "2001:db8::7")
                        answer = (packet[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + packet[12:]
                                  + b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(value)) + value)
                    else:
                        answer = packet
                    fixture.sendto(answer, peer)
                except socket.timeout:
                    continue
        worker = threading.Thread(target=responder, daemon=True)
        worker.start()
        try:
            for reuse in (False, True):
                remote, local = free_port(), free_port()
                server = {"log": {"level": "error"}, "inbounds": [{"type": "snell", "listen": "127.0.0.1",
                          "listen_port": remote, "version": 6, "psk": PSK, "mode": "default"}],
                          "outbounds": [{"type": "direct", "tag": "direct"}],
                          "route": {"rules": [{"action": "route", "outbound": "direct", "override_address": "127.0.0.1"}], "final": "direct"}}
                client = {"log": {"level": "error"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": local}],
                          "outbounds": [{"type": "snell", "tag": "vpn", "server": "127.0.0.1", "server_port": remote,
                                         "psk": PSK, "version": 6, "mode": "default", "reuse": reuse}], "route": {"final": "vpn"}}
                name = "reuse-" + str(reuse).lower()
                with contextlib.ExitStack() as stack:
                    if xray:
                        gateway = free_port()
                        access = out / (name + "-xray-access.log")
                        gateway_config = {"log": {"access": str(access), "loglevel": "warning"},
                                          "inbounds": [{"tag": "snell-socks", "listen": "127.0.0.1", "port": gateway,
                                                        "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}],
                                          "outbounds": [{"tag": "fixture-egress", "protocol": "freedom"}]}
                        gateway_process = stack.enter_context(process(xray, root, name + "-xray", gateway_config, out, xray=True))
                        server["outbounds"] = [{"type": "socks", "tag": "direct", "server": "127.0.0.1",
                                                "server_port": gateway, "version": "5"}]
                    stack.enter_context(process(core, root, name + "-server", server, out))
                    stack.enter_context(process(core, root, name + "-client", client, out))
                    for round_index in range(3):
                        for host in ("127.0.0.1", "snell.test"):
                            https(local, web.server_port, host, client_tls)
                            rows.append({"case": name + "/https/" + host, "round": round_index, "passed": True})
                        for qtype in (1, 28):
                            query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05snell\x04test\x00" + struct.pack("!HH", qtype, 1)
                            answer = udp(local, fixture.getsockname()[1], query)
                            expected = socket.inet_aton("192.0.2.7") if qtype == 1 else socket.inet_pton(socket.AF_INET6, "2001:db8::7")
                            assert answer[:4] == b"\x12\x34\x81\x80" and answer.endswith(expected)
                            rows.append({"case": name + "/udp-dns/" + str(qtype), "round": round_index, "passed": True})
                        transaction = os.urandom(12)
                        answer = udp(local, fixture.getsockname()[1], b"\x00\x01\x00\x00" + bytes.fromhex("2112a442") + transaction)
                        assert answer[:20] == b"\x01\x01\x00\x0c" + bytes.fromhex("2112a442") + transaction
                        assert answer[20:26] == b"\x00\x20\x00\x08\x00\x01"
                        assert bytes(a ^ b for a, b in zip(answer[28:32], bytes.fromhex("2112a442"))) == socket.inet_aton("127.0.0.1")
                        rows.append({"case": name + "/stun-binding", "round": round_index, "passed": True})
                    # An incorrect key must not reach the target, proving there is no client DIRECT fallback.
                    bad = json.loads(json.dumps(client))
                    bad["inbounds"][0]["listen_port"] = free_port()
                    bad["outbounds"][0]["psk"] = "wrong-synthetic-key"
                    with process(core, root, name + "-wrong-key", bad, out):
                        try:
                            https(bad["inbounds"][0]["listen_port"], web.server_port, "127.0.0.1", client_tls)
                        except (OSError, EOFError, AssertionError):
                            rows.append({"case": name + "/wrong-psk-rejected", "passed": True})
                        else:
                            raise AssertionError("wrong PSK delivered HTTPS")
                    if xray:
                        gateway_process.terminate()
                        gateway_process.wait(5)
                        evidence = access.read_text()
                        for transport in ("tcp", "udp"):
                            assert "accepted " + transport + ":127.0.0.1:" in evidence, "Xray access evidence missing: " + transport
                            rows.append({"case": name + "/xray-access/" + transport, "passed": True})
                        for transport, probe in (("tcp", lambda: https(local, web.server_port, "127.0.0.1", client_tls)),
                                                 ("udp", lambda: udp(local, fixture.getsockname()[1], b"stopped-xray-probe"))):
                            try:
                                probe()
                            except (OSError, EOFError, AssertionError):
                                rows.append({"case": name + "/xray-stopped-no-fallback/" + transport, "passed": True})
                            else:
                                raise AssertionError("traffic bypassed stopped Xray: " + transport)
            summary["synthetic_uri"] = "snell://" + PSK + "@192.0.2.1:20000/?" + urlencode({"version": 6, "mode": "default", "reuse": "true", "udp-relay": "true"}) + "#Snell6-local-example"
        except Exception as e:
            rows.append({"case": "execution", "passed": False, "error": type(e).__name__ + ": " + str(e)})
        finally:
            stop.set()
            worker.join(1)
            fixture.close()
            web.shutdown()
            web.server_close()
    summary["seconds"] = round(time.monotonic() - started, 2)
    summary["passed"] = len(rows) == (40 if xray else 32) and all(row["passed"] for row in rows)
    (out / "results.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps({"passed": summary["passed"], "checks": len(rows), "seconds": summary["seconds"]}))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tls-fixture", type=Path, help="Existing local test cert.pem/key.pem; avoids cryptography dependency")
    parser.add_argument("--xray", type=Path, help="Optional Xray binary to qualify the SOCKS5 gateway path")
    args = parser.parse_args()
    raise SystemExit(run(args.core.resolve(), args.out.resolve(), args.tls_fixture, args.xray))
