"""Loopback-only real-core Snell v6 modes with a shared PSK.

Reuses the HTTPS/SOCKS helpers from snell6_local_acceptance. All keys are
synthetic. Negative cases verify that no application payload reached fixtures.
Use an isolated network namespace when running unsafe-raw on Linux.
"""
import argparse
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time

import snell6_local_acceptance as base


def run(core, out):
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    started = time.monotonic()
    summary = {"scope": "loopback same-core server/client; modes and shared PSK",
               "external_network": False, "core_sha256": hashlib.sha256(core.read_bytes()).hexdigest(),
               "core_version": subprocess.check_output([str(core), "version"], text=True, timeout=10),
               "cases": rows}
    counts = {"tcp": 0, "udp": 0}

    class HTTP(base.HTTP):
        def do_GET(self):
            counts["tcp"] += 1
            super().do_GET()

    with tempfile.TemporaryDirectory(prefix="snell6-modes-") as tmp:
        root = Path(tmp)
        cert, key = base.certificate(root)
        tls_server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_server.load_cert_chain(cert, key)
        tls_client = ssl.create_default_context(cafile=str(cert))
        web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HTTP)
        web.socket = tls_server.wrap_socket(web.socket, server_side=True)
        threading.Thread(target=web.serve_forever, daemon=True).start()
        echo = socket.socket(type=socket.SOCK_DGRAM)
        echo.bind(("127.0.0.1", 0))
        echo.settimeout(.1)
        stop = threading.Event()

        def responder():
            while not stop.is_set():
                try:
                    packet, peer = echo.recvfrom(65535)
                    counts["udp"] += 1
                    echo.sendto(packet, peer)
                except socket.timeout:
                    continue

        worker = threading.Thread(target=responder, daemon=True)
        worker.start()
        sequence = 0

        def probe(server_port, mode, reuse, label, psk=base.PSK, allowed=True, client_mode=None):
            nonlocal sequence
            sequence += 1
            local = base.free_port()
            outbound = {"type": "snell", "tag": "vpn", "server": "127.0.0.1",
                        "server_port": server_port, "version": 6, "mode": client_mode or mode,
                        "psk": psk, "reuse": reuse}
            client = {"log": {"level": "error"},
                      "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": local}],
                      "outbounds": [outbound], "route": {"final": "vpn"}}
            name = f"{sequence}-{mode}-reuse-{str(reuse).lower()}-{label}"
            payload = ("synthetic-" + name).encode()
            with base.process(core, root, name, client, out):
                for transport, action in (
                    ("tcp", lambda: base.https(local, web.server_port, "127.0.0.1", tls_client)),
                    ("udp", lambda: base.udp(local, echo.getsockname()[1], payload)),
                ):
                    before = counts[transport]
                    try:
                        result = action()
                    except (OSError, EOFError, AssertionError):
                        if allowed:
                            raise
                        time.sleep(.1)
                        assert counts[transport] == before, "denied payload reached fixture"
                    else:
                        assert allowed, "unauthorized request returned application data"
                        if transport == "udp":
                            assert result == payload, "UDP payload mismatch"
                        assert counts[transport] > before, "fixture delivery evidence missing"
                    rows.append({"mode": mode, "reuse": reuse, "case": label,
                                 "transport": transport, "expected": "delivered" if allowed else "rejected",
                                 "fixture_deliveries": counts[transport] - before, "passed": True})

        try:
            for mode in ("default", "unshaped", "unsafe-raw"):
                for reuse in (False, True):
                    remote = base.free_port()
                    server = {"log": {"level": "error"},
                              "inbounds": [{"type": "snell", "listen": "127.0.0.1", "listen_port": remote,
                                            "version": 6, "mode": mode, "psk": base.PSK}],
                              "outbounds": [{"type": "direct", "tag": "direct"}],
                              "route": {"rules": [{"action": "route", "outbound": "direct",
                                                    "override_address": "127.0.0.1"}], "final": "direct"}}
                    prefix = f"server-{mode}-{str(reuse).lower()}"
                    with base.process(core, root, prefix + "-psk", server, out):
                        probe(remote, mode, reuse, "psk-only")
                        probe(remote, mode, reuse,
                              "raw-psk-not-authenticated" if mode == "unsafe-raw" else "wrong-psk",
                              psk="wrong-synthetic-key", allowed=mode == "unsafe-raw")
                        for other in ("default", "unshaped", "unsafe-raw"):
                            if other != mode:
                                probe(remote, mode, reuse, "mode-mismatch-" + other,
                                      allowed=False, client_mode=other)
            summary["passed"] = len(rows) == 48 and all(row["passed"] for row in rows)
        except Exception as exc:
            rows.append({"case": "execution", "passed": False,
                         "error": type(exc).__name__ + ": " + str(exc)})
            summary["passed"] = False
        finally:
            stop.set()
            worker.join(1)
            echo.close()
            web.shutdown()
            web.server_close()
    summary["seconds"] = round(time.monotonic() - started, 2)
    (out / "results.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": summary["passed"], "checks": len(rows), "seconds": summary["seconds"]}))
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(run(args.core.resolve(), args.out.resolve()))
