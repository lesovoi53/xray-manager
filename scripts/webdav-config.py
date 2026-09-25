#!/usr/bin/env python3
"""Render secret-bearing YAML atomically, without logging credentials."""
import json
import os
from pathlib import Path
import tempfile


def render(env):
    backends = []
    for enabled, url, login, password in (
        (env.get("MULTI_LOCAL_ENABLED", "true"), "http://%s:%s" % (env["SERVER_IP"], env["SELFHOSTED_PORT"]), env["SELFHOSTED_LOGIN"], env["SELFHOSTED_PASSWORD"]),
        (env.get("MULTI_MAILRU_ENABLED", "true"), "https://webdav.cloud.mail.ru", env.get("MAILRU_LOGIN"), env.get("MAILRU_PASSWORD")),
        (env.get("MULTI_YANDEX_ENABLED", "false"), "https://webdav.yandex.ru", env.get("YANDEX_LOGIN"), env.get("YANDEX_PASSWORD")),
        (env.get("MULTI_CUSTOM_ENABLED", "false"), env.get("CUSTOM_URL"), env.get("CUSTOM_LOGIN"), env.get("CUSTOM_PASSWORD")),
    ):
        if enabled == "true" and url and login and password:
            backends.append((url, login, password))
    if not backends:
        raise ValueError("WebDAV multi: no configured active backends")
    text = """mode: server
timeout: 60s
tuning:
  chunk-size: 131071
  coalesce: 10ms
  poll-max: 500ms
  poll-min: 200ms
  puts: 8
  read-max: 8
  read-min: 3
backends:
"""
    for url, login, password in backends:
        text += "  - url: %s\n    login: %s\n    password: %s\n" % tuple(json.dumps(v, ensure_ascii=False) for v in (url, login, password))
    if env.get("WEBDAV_ENC") in ("true", "1"):
        text += "enc: true\n"
    return text


if __name__ == "__main__":
    target = Path("/etc/webdav-tunnel/webdav-tunnel.yaml")
    output = render(os.environ)
    fd, temporary = tempfile.mkstemp(prefix=".webdav-", dir=target.parent)
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(f.fileno(), 0o660)
            f.write(output)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
