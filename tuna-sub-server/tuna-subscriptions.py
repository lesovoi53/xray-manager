#!/usr/bin/env python3
"""
TUNA Subscription Server (tuna-subscriptions)
Автономный, легковесный локальный HTTP-сервис подписок для панели TUNA.
Реализация на стандартной библиотеке Python 3 (Zero Dependencies).
"""

import sys
import os
import re
import json
import uuid
import base64
import hashlib
import secrets
import sqlite3
import datetime
from http import HTTPStatus
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# Поддержка tomllib (Python 3.11+) с fallback-парсером для более старых версий
try:
    import tomllib
except ImportError:
    tomllib = None

# Конфигурация по умолчанию
DEFAULT_CONFIG = {
    "server": {
        "bind_address": "127.0.0.1",
        "port": 22217,
        "max_request_body_size": 65536,
    },
    "database": {
        "path": "/var/lib/tuna-subscriptions/subscriptions.db",
    },
    "limits": {
        "max_nickname_length": 64,
        "max_uri_length": 4096,
        "max_users": 1000,
    },
    "logging": {
        "file": "/var/log/tuna-subscriptions/service.log",
        "level": "INFO",
    },
}

def load_config(config_path=None):
    """Загрузка конфигурации из TOML или использование значений по умолчанию."""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if not config_path:
        for p in ["/etc/tuna-subscriptions/config.toml", "config.toml"]:
            if os.path.isfile(p):
                config_path = p
                break

    if config_path and os.path.isfile(config_path):
        try:
            with open(config_path, "rb") as f:
                if tomllib:
                    loaded = tomllib.load(f)
                else:
                    # Простой построчный fallback парсер для базового toml
                    loaded = {}
                    current_sec = loaded
                    for line in f.read().decode("utf-8").splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith("[") and line.endswith("]"):
                            sec = line[1:-1].strip()
                            current_sec = loaded.setdefault(sec, {})
                        elif "=" in line:
                            k, v = line.split("=", 1)
                            k, v = k.strip(), v.strip().strip('"').strip("'")
                            if v.isdigit():
                                v = int(v)
                            elif v.lower() == "true":
                                v = True
                            elif v.lower() == "false":
                                v = False
                            current_sec[k] = v
                for sec, vals in loaded.items():
                    if sec in cfg and isinstance(vals, dict):
                        cfg[sec].update(vals)
                    else:
                        cfg[sec] = vals
        except Exception as e:
            sys.stderr.write(f"[WARN] Failed to parse config {config_path}: {e}\n")
    return cfg

def init_database(db_path):
    """Инициализация SQLite базы данных в режиме WAL с гарантией атомарности."""
    db_dir = os.path.dirname(os.path.abspath(db_path))
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, mode=0o700, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("PRAGMA journal_mode = WAL;")
    c.execute("PRAGMA synchronous = NORMAL;")
    c.execute("PRAGMA foreign_keys = ON;")
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            nickname TEXT UNIQUE NOT NULL,
            csqtt_uri TEXT DEFAULT '',
            qwdtt_uri TEXT DEFAULT '',
            snell_uri TEXT DEFAULT '',
            mieru_uri TEXT DEFAULT '',
            masterdnsvpn_uri TEXT DEFAULT '',
            custom_uri TEXT DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            subscription_token_hash TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    # Миграция схемы: добавление custom_uri если таблица создана старой версией
    c.execute("PRAGMA table_info(users);")
    existing_cols = [col[1] for col in c.fetchall()]
    if "custom_uri" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN custom_uri TEXT DEFAULT '';")

    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname ON users(nickname);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(subscription_token_hash);")
    conn.commit()
    return conn

def hash_token(token: str) -> str:
    """Криптографический SHA-256 хеш токена подписки."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

def validate_single_uri(val: str, max_len: int = 4096) -> tuple[bool, str]:
    """
    Валидация одиночного URI:
    - Запрещены управляющие символы, CR, LF.
    - Проверка базовой длины.
    - Обязательное наличие схемы (://).
    - Разрешены пустые значения.
    """
    if not val:
        return True, ""
    if len(val) > max_len:
        return False, f"URI exceeds max length of {max_len}"
    if "\r" in val or "\n" in val:
        return False, "URI contains newline or carriage return"
    if "://" not in val:
        return False, "URI must contain scheme (://)"
    # Проверка на управляющие символы ASCII (0x00-0x1F, 0x7F)
    for ch in val:
        if ord(ch) < 32 or ord(ch) == 127:
            return False, "URI contains invalid control characters"
    return True, ""

def normalize_and_validate_uris(raw_val, max_len: int = 4096) -> tuple[bool, str, str]:
    """
    Нормализует входящие URI (одиночная строка, многострочный текст или массив/список строк)
    в единую строку с разделителем '\n'. Валидирует каждую ссылку.
    Возвращает: (is_valid, error_message, normalized_string)
    """
    if raw_val is None:
        return True, "", ""

    items = []
    if isinstance(raw_val, (list, tuple)):
        for el in raw_val:
            if not isinstance(el, str):
                return False, "Each URI in array must be a string", ""
            for line in el.splitlines():
                s = line.strip()
                if s:
                    items.append(s)
    elif isinstance(raw_val, str):
        for line in raw_val.splitlines():
            s = line.strip()
            if s:
                items.append(s)
    else:
        return False, "URI field must be a string or array of strings", ""

    if not items:
        return True, "", ""

    for item in items:
        ok, err = validate_single_uri(item, max_len)
        if not ok:
            return False, err, ""

    return True, "", "\n".join(items)

def validate_uri(val, max_len: int = 4096) -> tuple[bool, str]:
    """Обратная совместимость: валидация одного или нескольких URI."""
    ok, err, _ = normalize_and_validate_uris(val, max_len)
    return ok, err

def validate_nickname(nick: str, max_len: int = 64) -> tuple[bool, str]:
    """Валидация никнейма: UTF-8, длина, отсутствие переносов строк."""
    if not nick or not nick.strip():
        return False, "Nickname is required"
    nick = nick.strip()
    if len(nick) > max_len:
        return False, f"Nickname exceeds max length of {max_len}"
    if "\r" in nick or "\n" in nick:
        return False, "Nickname contains newlines"
    return True, ""

class SubscriptionApp:
    def __init__(self, config):
        self.config = config
        self.db_path = config["database"]["path"]
        self.conn = init_database(self.db_path)
        self.bind_addr = config["server"]["bind_address"]
        self.bind_port = config["server"]["port"]
        self.max_nick_len = config["limits"]["max_nickname_length"]
        self.max_uri_len = config["limits"]["max_uri_length"]
        self.max_users = config["limits"]["max_users"]

    def create_user(self, data: dict) -> tuple[int, dict]:
        nickname = str(data.get("nickname") or "").strip()
        ok, err = validate_nickname(nickname, self.max_nick_len)
        if not ok:
            return 400, {"error": err}

        # Поддерживаемые поля ссылок (строка или массив, с суффиксами и без)
        field_specs = [
            ("csqtt", ["csqtt_uri", "csqtt_uris", "csqtt"]),
            ("qwdtt", ["qwdtt_uri", "qwdtt_uris", "qwdtt"]),
            ("snell", ["snell_uri", "snell_uris", "snell"]),
            ("mieru", ["mieru_uri", "mieru_uris", "mieru"]),
            ("masterdnsvpn", ["masterdnsvpn_uri", "masterdnsvpn_uris", "masterdnsvpn", "dns_uri", "stormdns_uri", "dns"]),
            ("custom", ["custom_uri", "custom_uris", "custom"])
        ]

        normalized_fields = {}
        for name, keys in field_specs:
            val = None
            for k in keys:
                if k in data and data[k] is not None:
                    val = data[k]
                    break
            valid, v_err, norm_val = normalize_and_validate_uris(val, self.max_uri_len)
            if not valid:
                return 400, {"error": f"Invalid {name}: {v_err}"}
            normalized_fields[name] = norm_val

        csqtt = normalized_fields["csqtt"]
        qwdtt = normalized_fields["qwdtt"]
        snell = normalized_fields["snell"]
        mieru = normalized_fields["mieru"]
        dns   = normalized_fields["masterdnsvpn"]
        custom = normalized_fields["custom"]

        # Генерация криптографически стойкого токена
        raw_token = secrets.token_urlsafe(32)
        tok_hash = hash_token(raw_token)
        u_id = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            with self.conn:
                c = self.conn.cursor()
                # Проверка лимита пользователей
                c.execute("SELECT COUNT(*) FROM users;")
                if c.fetchone()[0] >= self.max_users:
                    return 403, {"error": f"Maximum user capacity reached ({self.max_users})"}

                c.execute("""
                    INSERT INTO users (id, nickname, csqtt_uri, qwdtt_uri, snell_uri, mieru_uri, masterdnsvpn_uri, custom_uri,
                                       enabled, subscription_token_hash, revision, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 1, ?, ?);
                """, (u_id, nickname, csqtt, qwdtt, snell, mieru, dns, custom, tok_hash, now, now))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{nickname}' already exists"}
        except Exception as e:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in normalized_fields.values() if v)
        sub_url = f"http://{self.bind_addr}:{self.bind_port}/sub/{raw_token}"
        return 201, {
            "id": u_id,
            "nickname": nickname,
            "subscription_url": sub_url,
            "token": raw_token,
            "revision": 1,
            "enabled": True,
            "total_uris": total_uris,
            "created_at": now,
            "updated_at": now
        }

    def list_users(self) -> tuple[int, list]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users ORDER BY created_at DESC;")
        users = []
        for r in c.fetchall():
            csqtt_list = [u for u in (r["csqtt_uri"] or "").splitlines() if u.strip()]
            qwdtt_list = [u for u in (r["qwdtt_uri"] or "").splitlines() if u.strip()]
            snell_list = [u for u in (r["snell_uri"] or "").splitlines() if u.strip()]
            mieru_list = [u for u in (r["mieru_uri"] or "").splitlines() if u.strip()]
            dns_list   = [u for u in (r["masterdnsvpn_uri"] or "").splitlines() if u.strip()]
            custom_val = r["custom_uri"] if "custom_uri" in r.keys() else ""
            custom_list = [u for u in (custom_val or "").splitlines() if u.strip()]
            total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list)

            users.append({
                "id": r["id"],
                "nickname": r["nickname"],
                "enabled": bool(r["enabled"]),
                "revision": r["revision"],
                "total_uris": total_uris,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "protocols": {
                    "csqtt": len(csqtt_list) > 0,
                    "qwdtt": len(qwdtt_list) > 0,
                    "snell": len(snell_list) > 0,
                    "mieru": len(mieru_list) > 0,
                    "masterdnsvpn": len(dns_list) > 0,
                    "custom": len(custom_list) > 0,
                },
                "counts": {
                    "csqtt": len(csqtt_list),
                    "qwdtt": len(qwdtt_list),
                    "snell": len(snell_list),
                    "mieru": len(mieru_list),
                    "masterdnsvpn": len(dns_list),
                    "custom": len(custom_list),
                }
            })
        return 200, users

    def get_user(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        r = c.fetchone()
        if not r:
            return 404, {"error": "User not found"}

        csqtt_list = [u for u in (r["csqtt_uri"] or "").splitlines() if u.strip()]
        qwdtt_list = [u for u in (r["qwdtt_uri"] or "").splitlines() if u.strip()]
        snell_list = [u for u in (r["snell_uri"] or "").splitlines() if u.strip()]
        mieru_list = [u for u in (r["mieru_uri"] or "").splitlines() if u.strip()]
        dns_list   = [u for u in (r["masterdnsvpn_uri"] or "").splitlines() if u.strip()]
        custom_val = r["custom_uri"] if "custom_uri" in r.keys() else ""
        custom_list = [u for u in (custom_val or "").splitlines() if u.strip()]
        total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list)

        return 200, {
            "id": r["id"],
            "nickname": r["nickname"],
            "csqtt": r["csqtt_uri"],
            "qwdtt": r["qwdtt_uri"],
            "snell": r["snell_uri"],
            "mieru": r["mieru_uri"],
            "masterdnsvpn": r["masterdnsvpn_uri"],
            "custom": custom_val,
            "csqtt_uris": csqtt_list,
            "qwdtt_uris": qwdtt_list,
            "snell_uris": snell_list,
            "mieru_uris": mieru_list,
            "masterdnsvpn_uris": dns_list,
            "custom_uris": custom_list,
            "total_uris": total_uris,
            "enabled": bool(r["enabled"]),
            "revision": r["revision"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"]
        }

    def update_user(self, user_id: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?;", (user_id,))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        new_nick = cur["nickname"]
        if "nickname" in data:
            candidate_nick = str(data["nickname"]).strip()
            ok, err = validate_nickname(candidate_nick, self.max_nick_len)
            if not ok:
                return 400, {"error": err}
            new_nick = candidate_nick

        field_specs = [
            ("csqtt", ["csqtt_uri", "csqtt_uris", "csqtt"], cur["csqtt_uri"]),
            ("qwdtt", ["qwdtt_uri", "qwdtt_uris", "qwdtt"], cur["qwdtt_uri"]),
            ("snell", ["snell_uri", "snell_uris", "snell"], cur["snell_uri"]),
            ("mieru", ["mieru_uri", "mieru_uris", "mieru"], cur["mieru_uri"]),
            ("masterdnsvpn", ["masterdnsvpn_uri", "masterdnsvpn_uris", "masterdnsvpn", "dns_uri", "stormdns_uri", "dns"], cur["masterdnsvpn_uri"]),
            ("custom", ["custom_uri", "custom_uris", "custom"], cur["custom_uri"] if "custom_uri" in cur.keys() else ""),
        ]

        updated_fields = {}
        for name, keys, current_val in field_specs:
            found = False
            raw_val = None
            for k in keys:
                if k in data:
                    found = True
                    raw_val = data[k]
                    break
            if found:
                ok, err, norm_val = normalize_and_validate_uris(raw_val, self.max_uri_len)
                if not ok:
                    return 400, {"error": f"Invalid {name}: {err}"}
                updated_fields[name] = norm_val
            else:
                updated_fields[name] = current_val

        new_enabled = cur["enabled"]
        if "enabled" in data:
            new_enabled = 1 if data["enabled"] else 0

        new_revision = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            with self.conn:
                c.execute("""
                    UPDATE users
                    SET nickname = ?, csqtt_uri = ?, qwdtt_uri = ?, snell_uri = ?, mieru_uri = ?,
                        masterdnsvpn_uri = ?, custom_uri = ?, enabled = ?, revision = ?, updated_at = ?
                    WHERE id = ?;
                """, (new_nick, updated_fields["csqtt"], updated_fields["qwdtt"], updated_fields["snell"],
                      updated_fields["mieru"], updated_fields["masterdnsvpn"], updated_fields["custom"],
                      new_enabled, new_revision, now, user_id))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{new_nick}' already exists"}
        except Exception:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in updated_fields.values() if v)

        return 200, {
            "id": user_id,
            "nickname": new_nick,
            "csqtt": updated_fields["csqtt"],
            "qwdtt": updated_fields["qwdtt"],
            "snell": updated_fields["snell"],
            "mieru": updated_fields["mieru"],
            "masterdnsvpn": updated_fields["masterdnsvpn"],
            "custom": updated_fields["custom"],
            "csqtt_uris": [u for u in updated_fields["csqtt"].splitlines() if u.strip()],
            "qwdtt_uris": [u for u in updated_fields["qwdtt"].splitlines() if u.strip()],
            "snell_uris": [u for u in updated_fields["snell"].splitlines() if u.strip()],
            "mieru_uris": [u for u in updated_fields["mieru"].splitlines() if u.strip()],
            "masterdnsvpn_uris": [u for u in updated_fields["masterdnsvpn"].splitlines() if u.strip()],
            "custom_uris": [u for u in updated_fields["custom"].splitlines() if u.strip()],
            "total_uris": total_uris,
            "enabled": bool(new_enabled),
            "revision": new_revision,
            "updated_at": now
        }

    def delete_user(self, user_id: str) -> tuple[int, dict]:
        with self.conn:
            c = self.conn.cursor()
            c.execute("DELETE FROM users WHERE id = ?;", (user_id,))
            if c.rowcount == 0:
                return 404, {"error": "User not found"}
        return 200, {"success": True, "message": "User deleted successfully"}

    def rotate_token(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT id, revision FROM users WHERE id = ?;", (user_id,))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        new_raw_token = secrets.token_urlsafe(32)
        new_tok_hash = hash_token(new_raw_token)
        new_rev = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.conn:
            c.execute("""
                UPDATE users
                SET subscription_token_hash = ?, revision = ?, updated_at = ?
                WHERE id = ?;
            """, (new_tok_hash, new_rev, now, user_id))

        sub_url = f"http://{self.bind_addr}:{self.bind_port}/sub/{new_raw_token}"
        return 200, {
            "id": user_id,
            "subscription_url": sub_url,
            "token": new_raw_token,
            "revision": new_rev,
            "updated_at": now
        }

    def get_subscription_payload(self, token: str, if_none_match: str = None) -> tuple[int, dict, bytes]:
        """
        Выдача подписки по токену:
        - Поиск по SHA256(token).
        - Все протоколы в строгом порядке: CSQTT -> WDTT -> Snell -> Mieru -> MasterDNS -> Custom.
        - Все ссылки каждого протокола разбиваются построчно.
        - Фильтрация пустых.
        - Если все пусты -> 204 No Content.
        - ETag и 304 Not Modified.
        - Base64 UTF-8.
        """
        tok_hash = hash_token(token)
        c = self.conn.cursor()
        c.execute("""
            SELECT * FROM users WHERE subscription_token_hash = ?;
        """, (tok_hash,))
        user = c.fetchone()

        if not user or not user["enabled"]:
            return 404, {"error": "Subscription not found or disabled"}, b""

        candidate_fields = [
            user["csqtt_uri"],
            user["qwdtt_uri"],
            user["snell_uri"],
            user["mieru_uri"],
            user["masterdnsvpn_uri"],
            user["custom_uri"] if "custom_uri" in user.keys() else ""
        ]

        non_empty = []
        for field_val in candidate_fields:
            if field_val and str(field_val).strip():
                for line in str(field_val).splitlines():
                    clean = line.strip()
                    if clean:
                        non_empty.append(clean)

        if not non_empty:
            return 204, {}, b""

        raw_text = "\n".join(non_empty) + "\n"
        raw_bytes = raw_text.encode("utf-8")
        b64_payload = base64.b64encode(raw_bytes)

        # Вычисление детерминированного ETag
        content_hash = hashlib.sha256(raw_bytes).hexdigest()[:16]
        etag = f'"{user["revision"]}-{content_hash}"'

        headers = {
            "Content-Type": "text/plain; charset=utf-8",
            "Cache-Control": "private, no-store",
            "ETag": etag,
            "Profile-Title": user["nickname"],
        }

        if if_none_match and if_none_match.strip() == etag:
            return 304, headers, b""

        return 200, headers, b64_payload


class SubscriptionRequestHandler(BaseHTTPRequestHandler):
    server_version = "TunaSubscription/1.0"

    @property
    def app(self) -> SubscriptionApp:
        return self.server.app

    def log_message(self, format, *args):
        """
        Маскирование логов: НИКОГДА не выводить секретные токены подписок и сырые URI.
        """
        msg = format % args
        # Замена токенов в путях /sub/...
        sanitized = re.sub(r'/sub/[a-zA-Z0-9_\-]+', '/sub/[REDACTED_TOKEN]', msg)
        log_file = self.app.config.get("logging", {}).get("file")
        log_entry = f"[{self.log_date_time_string()}] {self.client_address[0]} {sanitized}\n"
        if log_file:
            try:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(log_entry)
                return
            except Exception:
                pass
        sys.stderr.write(log_entry)

    def send_json(self, status_code: int, data: any):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> dict:
        content_len = int(self.headers.get("Content-Length", 0))
        max_size = self.app.config["server"]["max_request_body_size"]
        if content_len > max_size:
            raise ValueError("Payload Too Large")
        if content_len <= 0:
            return {}
        raw = self.rfile.read(content_len)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid JSON format")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Публичная выдача подписки: /sub/<secret-token>
        if path.startswith("/sub/"):
            token = path[len("/sub/"):]
            if not token:
                self.send_error(HTTPStatus.NOT_FOUND, "Token missing")
                return

            if_none_match = self.headers.get("If-None-Match")
            status, headers, payload = self.app.get_subscription_payload(token, if_none_match)

            if status == 304:
                self.send_response(HTTPStatus.NOT_MODIFIED)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.end_headers()
                return

            if status == 204:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()
                return

            if status != 200:
                self.send_error(HTTPStatus.NOT_FOUND, "Subscription not found")
                return

            self.send_response(HTTPStatus.OK)
            for k, v in headers.items():
                # Profile-Title в заголовок UTF-8
                if k == "Profile-Title":
                    try:
                        v.encode("latin-1")
                        self.send_header(k, v)
                    except UnicodeEncodeError:
                        # RFC 5987 совместимый заголовок для UTF-8
                        from urllib.parse import quote
                        self.send_header(k, quote(v.encode("utf-8")))
                else:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        # Управляющий API: GET /api/users
        if path == "/api/users":
            status, res = self.app.list_users()
            self.send_json(status, res)
            return

        # GET /api/users/<id>
        m_user = re.match(r"^/api/users/([a-zA-Z0-9_\-]+)$", path)
        if m_user:
            user_id = m_user.group(1)
            status, res = self.app.get_user(user_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id>/subscription-url
        m_sub_url = re.match(r"^/api/users/([a-zA-Z0-9_\-]+)/subscription-url$", path)
        if m_sub_url:
            user_id = m_sub_url.group(1)
            status, res = self.app.get_user(user_id)
            if status != 200:
                self.send_json(status, res)
                return
            self.send_json(200, {
                "id": user_id,
                "nickname": res["nickname"],
                "subscription_url_template": f"http://{self.app.bind_addr}:{self.app.bind_port}/sub/<token>",
                "note": "Full token is only shown upon user creation or rotation (/api/users/<id>/rotate-token)"
            })
            return

        # Healthcheck
        if path == "/health" or path == "/api/health":
            self.send_json(200, {"status": "ok", "service": "tuna-subscriptions"})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # POST /api/users
        if path == "/api/users":
            try:
                data = self.read_json_body()
            except ValueError as e:
                self.send_json(400, {"error": str(e)})
                return
            status, res = self.app.create_user(data)
            self.send_json(status, res)
            return

        # POST /api/users/<id>/rotate-token
        m_rotate = re.match(r"^/api/users/([a-zA-Z0-9_\-]+)/rotate-token$", path)
        if m_rotate:
            user_id = m_rotate.group(1)
            status, res = self.app.rotate_token(user_id)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # PUT /api/users/<id>
        m_user = re.match(r"^/api/users/([a-zA-Z0-9_\-]+)$", path)
        if m_user:
            user_id = m_user.group(1)
            try:
                data = self.read_json_body()
            except ValueError as e:
                self.send_json(400, {"error": str(e)})
                return
            status, res = self.app.update_user(user_id, data)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # DELETE /api/users/<id>
        m_user = re.match(r"^/api/users/([a-zA-Z0-9_\-]+)$", path)
        if m_user:
            user_id = m_user.group(1)
            status, res = self.app.delete_user(user_id)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")


def run_server(config_path=None):
    config = load_config(config_path)
    bind_ip = config["server"]["bind_address"]
    port = int(config["server"]["port"])

    app = SubscriptionApp(config)
    server_address = (bind_ip, port)

    httpd = ThreadingHTTPServer(server_address, SubscriptionRequestHandler)
    httpd.app = app

    sys.stdout.write(f"[INFO] TUNA Subscription Server listening on http://{bind_ip}:{port}\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\n[INFO] Stopping server...\n")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    cfg_p = None
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--config", "-c") and len(sys.argv) > 2:
            cfg_p = sys.argv[2]
        elif not sys.argv[1].startswith("-"):
            cfg_p = sys.argv[1]
    run_server(cfg_p)
