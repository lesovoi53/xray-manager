#!/usr/bin/env python3
"""Discover existing gateways and add missing ones in one SQLite transaction.

Never overwrite an inbound or steal a port. Values in existing records, including
credentials and client UUIDs, are left byte-for-byte unchanged.
"""
import json
import os
import sqlite3
import sys


def configure(path):
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    messages = []
    try:
        connection.execute("BEGIN IMMEDIATE")
        rows = list(connection.execute("SELECT * FROM inbounds"))
        found = {}
        for row in rows:
            stream = json.loads(row["stream_settings"] or "{}")
            settings = json.loads(row["settings"] or "{}")
            if row["protocol"] in ("socks", "mixed") and row["enable"]:
                # Egress has no credentials: do not select an authenticated/public proxy.
                if settings.get("auth", "noauth") == "noauth" and row["listen"] in ("127.0.0.1", "::1"):
                    found.setdefault("SOCKS", row["port"])
            elif row["protocol"] == "dokodemo-door" and row["enable"] and settings.get("followRedirect"):
                key = "TPROXY" if stream.get("sockopt", {}).get("tproxy") == "tproxy" else "REDIRECT"
                found.setdefault(key, row["port"])
        definitions = {
            "SOCKS": (10808, "mixed", "in-mixed-gateway", {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}, {}, {"enabled": False}),
            "TPROXY": (12345, "dokodemo-door", "in-tproxy-gateway", {"network": "tcp,udp", "followRedirect": True}, {"sockopt": {"tproxy": "tproxy"}}, {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}),
            "REDIRECT": (12346, "dokodemo-door", "in-redirect-gateway", {"network": "tcp,udp", "followRedirect": True}, {}, {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}),
        }
        for key, definition in list(definitions.items()):
            definitions[key] = (int(os.environ.get("XRAY_" + key + "_PORT", definition[0])),) + definition[1:]
        template_row = connection.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
        template = json.loads(template_row[0]) if template_row else None
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
