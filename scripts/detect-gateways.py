#!/usr/bin/env python3
"""Discover existing gateways and add missing ones in one SQLite transaction.

Never overwrite an inbound or steal a port. Values in existing records, including
credentials and client UUIDs, are left byte-for-byte unchanged.
"""
import json
import os
import sqlite3
import sys

import importlib.util
from pathlib import Path
_spec = importlib.util.spec_from_file_location('xray_gateways', Path(__file__).with_name('xray_gateways.py'))
_gateways = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gateways)


def configure(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    messages = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        found, rows, template = _gateways.panel_gateways(connection, os.environ)
        definitions = {
            "SOCKS": (10808, "mixed", "in-mixed-gateway", {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, {}, {"enabled": False}),
            "TPROXY": (12345, "dokodemo-door", "in-tproxy-gateway", {"network": "tcp,udp", "followRedirect": True}, {"sockopt": {"tproxy": "tproxy"}}, {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}),
            "REDIRECT": (12346, "dokodemo-door", "in-redirect-gateway", {"network": "tcp,udp", "followRedirect": True}, {}, {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}),
        }
        for key, definition in list(definitions.items()):
            definitions[key] = (int(os.environ.get("XRAY_" + key + "_PORT", definition[0])),) + definition[1:]
        template_inbounds = template.get("inbounds", []) if template else []
        changed = False
        for key, (port, protocol, tag, settings, stream, sniffing) in definitions.items():
            if key not in found:
                if any(row["port"] == port or row["tag"] == tag for row in rows) or any(ib.get("port") == port or ib.get("tag") == tag for ib in template_inbounds):
                    raise ValueError("Gateway %s conflicts with existing configuration on port %d; preserve it and configure gateways explicitly" % (key, port))
                connection.execute("""INSERT INTO inbounds
                    (user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, stream_settings, tag, sniffing)
                    VALUES (1, 0, 0, 0, ?, 1, 0, '127.0.0.1', ?, ?, ?, ?, ?, ?)""",
                    (key + " Gateway", port, protocol, json.dumps(settings), json.dumps(stream), tag, json.dumps(sniffing)))
                found[key] = port
                changed = True
            messages.append("FOUND_%s=%d" % (key, found[key]))
        if template is not None:
            # Keep existing routing decisions. Add a default kill-switch only where absent.
            balancers = template.get("routing", {}).get("balancers", [])
            need_blocked = any(not b.get("fallbackTag") for b in balancers)
            if need_blocked:
                outbounds = template.setdefault("outbounds", [])
                blocked = next((o for o in outbounds if o.get("tag") == "blocked"), None)
                if blocked and blocked.get("protocol") != "blackhole":
                    raise ValueError("Existing outbound 'blocked' is not blackhole")
                if not blocked:
                    outbounds.append({"protocol": "blackhole", "tag": "blocked", "settings": {}})
                for balancer in balancers:
                    if not balancer.get("fallbackTag"):
                        balancer["fallbackTag"] = "blocked"
                connection.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig'", (json.dumps(template, ensure_ascii=False),))
                changed = True
        connection.commit()
        if changed:
            messages.append("RELOAD_XUI=1")
        return messages
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        print("\n".join(configure(sys.argv[1])))
    except Exception as error:
        # Errors contain schema/port details, never the source configuration.
        print("Xray gateway migration failed: " + str(error), file=sys.stderr)
        sys.exit(1)
