#!/usr/bin/env python3
"""Read-only port planning. Never selects 443/8443 or changes saved settings."""
import json
import os
from pathlib import Path
import re
import shlex
import socket
import sqlite3
import sys
import importlib.util
from contextlib import closing

_spec = importlib.util.spec_from_file_location("xray_gateways", Path(__file__).with_name("xray_gateways.py"))
_gateways = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gateways)

FORBIDDEN = {443, 8443}


def envfile(path):
    result = {}
    if Path(path).exists():
        for line in Path(path).read_text().splitlines():
            if re.match(r"^[A-Z_][A-Z_0-9]*=", line):
                key, value = line.split("=", 1)
                tokens = shlex.split(value, comments=True)
                result[key] = tokens[0] if tokens else ""
    return result


def allowed(port):
    value = int(port)
    if not 1 <= value <= 65535 or value in FORBIDDEN:
        raise ValueError("Port %s is forbidden or invalid; existing settings were not changed" % value)
    return value


def free(port):
    if port in FORBIDDEN:
        return False
    sockets = []
    try:
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            sock = socket.socket(socket.AF_INET, kind)
            sockets.append(sock)
            sock.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        for sock in sockets:
            sock.close()


def choose(preferred, reserved, width=1):
    for start in [preferred] + list(range(20000, 60000 - width)):
        ports = range(start, start + width)
        if all(p not in reserved and free(p) for p in ports):
            reserved.update(ports)
            return start
    raise ValueError("No available permitted port range")


def plan(root=Path("/")):
    def path(name): return root / name.lstrip("/")
    saved = envfile(path("/etc/x-manager/gateways.env"))
    reserved = set(FORBIDDEN)
    db = path("/etc/x-ui/x-ui.db")
    if db.exists():
        with closing(sqlite3.connect("file:" + str(db) + "?mode=ro", uri=True)) as connection:
            connection.row_factory = sqlite3.Row
            preferred = dict(saved)
            preferred.update({k:v for k,v in os.environ.items() if k in ('XRAY_SOCKS_PORT','XRAY_REDIRECT_PORT','XRAY_TPROXY_PORT')})
            found, rows, template = _gateways.panel_gateways(connection, preferred)
            for row in rows:
                reserved.add(int(row['port']))
            for inbound in (template or {}).get('inbounds', []):
                if 'port' in inbound:
                    reserved.add(int(inbound['port']))
            for key, value in found.items():
                saved['XRAY_'+key+'_PORT'] = str(value)
    if not db.exists():
        spec = importlib.util.spec_from_file_location('xray_discovery', Path(__file__).with_name('xray-discovery.py'))
        discovery = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(discovery)
        for key, value in discovery.discover(discovery.paths(root)).items():
            if key in saved and int(saved[key]) != value:
                raise ValueError('Saved gateway conflicts with active Xray: ' + key)
            saved.setdefault(key, str(value))
    result = {}
    # Reserve all existing service ports before allocating any new ones.
    snell = path("/etc/snell/snell-server.conf")
    if snell.exists():
        match = re.search(r"^listen\s*=\s*.*:(\d+)\s*$", snell.read_text(), re.M)
        if not match:
            raise ValueError("Invalid Snell listen setting")
        result["SNELL_PORT"] = allowed(match[1])
    mita = path("/etc/mita/config.json")
    if mita.exists():
        bindings = json.loads(mita.read_text())["portBindings"]
        for binding in bindings:
            value = str(binding.get("portRange", binding.get("port", "")))
            bounds = value.split("-")
            first, last = allowed(bounds[0]), allowed(bounds[-1])
            if last < first or any(first <= p <= last for p in FORBIDDEN):
                raise ValueError("Mieru range includes a forbidden port")
            reserved.update(range(first, last + 1))
        result["MIERU_PORTS"] = str(bindings[0].get("portRange", bindings[0].get("port")))
        result["MIERU_PROTO"] = bindings[0]["protocol"]
    webdav = envfile(path("/etc/webdav-tunnel/config.env"))
    if webdav:
        value = webdav.get("WEBDAV_LISTEN", "").rsplit(":", 1)[-1] or webdav.get("SELFHOSTED_PORT", "8443")
        # Existing local listener settings require an explicit migration if forbidden.
        result["WDAV_PORT"] = allowed(value)
    for key, preferred in (("XRAY_TPROXY_PORT", 12345), ("XRAY_REDIRECT_PORT", 12346), ("XRAY_SOCKS_PORT", 10808)):
        if key in saved:
            result[key] = allowed(saved[key])
    reserved.update(v for v in result.values() if isinstance(v, int))
    for key, preferred in (("XRAY_TPROXY_PORT", 12345), ("XRAY_REDIRECT_PORT", 12346), ("XRAY_SOCKS_PORT", 10808), ("SNELL_PORT", 1488), ("WDAV_PORT", 18080)):
        if key not in result:
            result[key] = choose(preferred, reserved)
    if "MIERU_PORTS" not in result:
        start = choose(2020, reserved, 11)
        result["MIERU_PORTS"] = "%d-%d" % (start, start + 10)
        result["MIERU_PROTO"] = "TCP"
    modes = []
    for name in ('/etc/snell/routing.mode', '/etc/openflux/routing.mode'):
        modefile = path(name)
        if modefile.exists():
            mode = modefile.read_text().strip()
            if mode not in ('direct', 'xray'):
                raise ValueError('Invalid saved routing mode')
            modes.append(mode)
    if webdav.get('ROUTING_MODE'):
        if webdav['ROUTING_MODE'] not in ('direct', 'xray'):
            raise ValueError('Invalid saved WebDAV routing mode')
        modes.append(webdav['ROUTING_MODE'])
    result['DEFAULT_ROUTING'] = 'xray' if not modes or 'xray' in modes else 'direct'
    return result


if __name__ == "__main__":
    try:
        selected = plan()
        if sys.argv[1:] == ["--webdav-port"]:
            print(selected["WDAV_PORT"])
        else:
            for key, value in selected.items():
                print("export %s=%s" % (key, shlex.quote(str(value))))
    except (ValueError, KeyError, sqlite3.Error) as error:
        sys.exit("Port preflight failed: " + str(error))
