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
from urllib.parse import urlparse, unquote

# Поддержка tomllib (Python 3.11+) с fallback-парсером для более старых версий
try:
    import tomllib
except ImportError:
    tomllib = None

# Конфигурация по умолчанию
DEFAULT_CONFIG = {
    "server": {
        "bind_address": "0.0.0.0",
        "port": 22217,
        "public_host": "",
        "max_request_body_size": 2097152,  # 2 MiB
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

# Константы контракта OpenFlux v2
ALLOWED_OPENFLUX_TRANSPORTS = {"mailru", "boards", "cupsonline"}
ALLOWED_OPENFLUX_MODES = {"classic", "multistream"}
ALLOWED_OPENFLUX_CODECS = {"legacy", "batched"}
ALLOWED_BALANCER_STRATEGIES = {"roundRobin", "leastPing"}
OPENFLUX_V2_PREFIX = "openflux-bundle://v2/"
MAX_OPENFLUX_JSON_BYTES = 512 * 1024  # 512 KiB
MAX_OPENFLUX_URI_CHARS = 700000

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
            subscription_token TEXT DEFAULT '',
            subscription_token_hash TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    # Миграция схемы: добавление колонок если таблица создана старой версией
    c.execute("PRAGMA table_info(users);")
    existing_cols = [col[1] for col in c.fetchall()]
    if "custom_uri" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN custom_uri TEXT DEFAULT '';")
    if "subscription_token" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN subscription_token TEXT DEFAULT '';")

    # Автоматическое восстановление токенов для пользователей без токена
    c.execute("SELECT id FROM users WHERE subscription_token IS NULL OR subscription_token = '';")
    for missing in c.fetchall():
        gen_tok = secrets.token_urlsafe(32)
        gen_hash = hash_token(gen_tok)
        c.execute("UPDATE users SET subscription_token = ?, subscription_token_hash = ? WHERE id = ?;", (gen_tok, gen_hash, missing["id"]))

    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_nickname ON users(nickname);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_users_token_hash ON users(subscription_token_hash);")

    # Аддитивная схема для OpenFlux v2
    c.execute("""
        CREATE TABLE IF NOT EXISTS server_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)
    c.execute("SELECT value FROM server_metadata WHERE key = 'issuer_id';")
    iss_row = c.fetchone()
    if not iss_row or not iss_row["value"]:
        c.execute("INSERT OR REPLACE INTO server_metadata (key, value) VALUES ('issuer_id', ?);", (str(uuid.uuid4()),))

    c.execute("""
        CREATE TABLE IF NOT EXISTS openflux_groups (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            mode TEXT NOT NULL,
            transport TEXT NOT NULL,
            urls_json TEXT NOT NULL,
            codec TEXT NOT NULL DEFAULT 'legacy',
            encryption_key TEXT NOT NULL DEFAULT '',
            source_slot INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_openflux_groups_name ON openflux_groups(name);")

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_openflux_config (
            user_id TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            connection_id TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT 'TUNA-OpenFlux',
            mode TEXT NOT NULL DEFAULT 'classic',
            balancer_strategy TEXT NOT NULL DEFAULT 'roundRobin',
            revision INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS user_openflux_selection (
            user_id TEXT NOT NULL,
            group_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            PRIMARY KEY(user_id, group_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(group_id) REFERENCES openflux_groups(id) ON DELETE CASCADE
        );
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_of_sel_user ON user_openflux_selection(user_id, position);")
    c.execute("CREATE INDEX IF NOT EXISTS idx_user_of_sel_group ON user_openflux_selection(group_id);")

    conn.commit()
    return conn

def validate_openflux_url(val: str) -> tuple[bool, str]:
    """Проверка одного HTTPS URL документа для группы OpenFlux."""
    if not val or not isinstance(val, str):
        return False, "URL must be a non-empty string"
    s = val.strip()
    if not s:
        return False, "URL cannot be empty"
    if not s.startswith("https://"):
        return False, f"URL must start with 'https://' (got: {s[:30]})"
    if any(ch in s for ch in (" ", "\t", "\r", "\n")):
        return False, "URL cannot contain spaces or whitespace characters"
    for ch in s:
        if ord(ch) < 32 or ord(ch) == 127:
            return False, "URL contains invalid control characters"
    try:
        parsed = urlparse(s)
        if not parsed.scheme or not parsed.netloc:
            return False, "Malformed URL structure"
    except Exception:
        return False, "Failed to parse URL"
    return True, ""

def serialize_openflux_v2_bundle(payload: dict) -> tuple[bool, str, str]:
    """
    Каноническая сериализация JSON -> URL-Safe Base64 (без padding) -> openflux-bundle://v2/...
    Возвращает: (is_valid, error_msg, full_uri)
    """
    try:
        json_str = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        json_bytes = json_str.encode("utf-8")
        if len(json_bytes) > MAX_OPENFLUX_JSON_BYTES:
            return False, f"Decoded bundle JSON payload exceeds 512 KiB limit ({len(json_bytes)} bytes)", ""
        b64_url = base64.urlsafe_b64encode(json_bytes).decode("ascii").rstrip("=")
        full_uri = f"{OPENFLUX_V2_PREFIX}{b64_url}"
        if len(full_uri) > MAX_OPENFLUX_URI_CHARS:
            return False, f"Bundle URI exceeds 700,000 characters limit ({len(full_uri)})", ""
        return True, "", full_uri
    except Exception as e:
        return False, f"Serialization error: {e}", ""

def deserialize_openflux_v2_bundle(bundle_uri: str) -> tuple[bool, str, dict]:
    """
    Десериализация и валидация строки openflux-bundle://v2/<base64url>.
    Возвращает: (is_valid, error_msg, payload_dict)
    """
    if not bundle_uri.startswith(OPENFLUX_V2_PREFIX):
        return False, f"URI does not start with '{OPENFLUX_V2_PREFIX}'", {}
    b64_str = bundle_uri[len(OPENFLUX_V2_PREFIX):].strip()
    if not b64_str:
        return False, "Empty base64url payload in bundle URI", {}
    missing_padding = len(b64_str) % 4
    if missing_padding:
        b64_str += "=" * (4 - missing_padding)
    try:
        raw_bytes = base64.urlsafe_b64decode(b64_str.encode("ascii"))
    except Exception as e:
        return False, f"Invalid base64url encoding: {e}", {}
    if len(raw_bytes) > MAX_OPENFLUX_JSON_BYTES:
        return False, f"Decoded payload exceeds 512 KiB ({len(raw_bytes)} bytes)", {}
    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        return False, f"Invalid JSON payload: {e}", {}

    if not isinstance(data, dict):
        return False, "Bundle payload must be a JSON object", {}
    if data.get("schema") != "openflux-bundle":
        return False, f"Invalid schema '{data.get('schema')}', expected 'openflux-bundle'", {}
    if data.get("version") != 2:
        return False, f"Invalid version '{data.get('version')}', expected 2", {}
    for req_field in ("issuer_id", "id", "revision", "name", "mode", "balancer_strategy", "groups"):
        if req_field not in data:
            return False, f"Missing required root field '{req_field}'", {}

    if not isinstance(data["revision"], int) or data["revision"] < 1:
        return False, "Field 'revision' must be an integer >= 1", {}
    if data["mode"] not in ALLOWED_OPENFLUX_MODES:
        return False, f"Invalid bundle mode '{data['mode']}'", {}
    if data["balancer_strategy"] not in ALLOWED_BALANCER_STRATEGIES:
        return False, f"Invalid balancer_strategy '{data['balancer_strategy']}'", {}

    groups = data["groups"]
    if not isinstance(groups, list) or len(groups) < 1 or len(groups) > 8:
        return False, f"Field 'groups' must contain between 1 and 8 groups (got {len(groups) if isinstance(groups, list) else 'non-list'})", {}

    total_urls = 0
    seen_group_ids = set()
    for idx, grp in enumerate(groups):
        if not isinstance(grp, dict):
            return False, f"Group at index {idx} must be an object", {}
        for gf in ("id", "name", "mode", "transport", "urls", "codec", "encryption_key"):
            if gf not in grp:
                return False, f"Group {idx} is missing field '{gf}'", {}
        gid = grp["id"]
        if gid in seen_group_ids:
            return False, f"Duplicate group id '{gid}' in bundle", {}
        seen_group_ids.add(gid)
        if grp["mode"] not in ALLOWED_OPENFLUX_MODES:
            return False, f"Group '{gid}' has invalid mode '{grp['mode']}'", {}
        if grp["transport"] not in ALLOWED_OPENFLUX_TRANSPORTS:
            return False, f"Group '{gid}' has forbidden transport '{grp['transport']}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}", {}
        if grp["codec"] not in ALLOWED_OPENFLUX_CODECS:
            return False, f"Group '{gid}' has invalid codec '{grp['codec']}'", {}

        urls = grp["urls"]
        if not isinstance(urls, list):
            return False, f"Group '{gid}' urls must be a list", {}
        if grp["mode"] == "classic" and len(urls) != 1:
            return False, f"Group '{gid}' is in classic mode but has {len(urls)} URLs (must be exactly 1)", {}
        if grp["mode"] == "multistream" and not (1 <= len(urls) <= 4):
            return False, f"Group '{gid}' is in multistream mode but has {len(urls)} URLs (must be 1 to 4)", {}

        seen_u = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u)
            if not ok_u:
                return False, f"Group '{gid}' contains invalid URL: {err_u}", {}
            if u in seen_u:
                return False, f"Group '{gid}' contains duplicate URL: '{u}'", {}
            seen_u.add(u)
        total_urls += len(urls)

    if total_urls > 32:
        return False, f"Total URLs across bundle exceeds 32 (got {total_urls})", {}

    return True, "", data

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
        self.public_host = str(config["server"].get("public_host") or "").strip()
        self.max_nick_len = config["limits"]["max_nickname_length"]
        self.max_uri_len = config["limits"]["max_uri_length"]
        self.max_users = config["limits"]["max_users"]
        self.issuer_id = self.get_issuer_id()

    def get_issuer_id(self) -> str:
        c = self.conn.cursor()
        c.execute("SELECT value FROM server_metadata WHERE key = 'issuer_id';")
        r = c.fetchone()
        if r and r["value"]:
            return r["value"]
        new_id = str(uuid.uuid4())
        with self.conn:
            self.conn.execute("INSERT OR REPLACE INTO server_metadata (key, value) VALUES ('issuer_id', ?);", (new_id,))
        return new_id

    def get_sub_url(self, raw_token: str) -> str:
        if not raw_token:
            return ""
        if self.public_host:
            host = self.public_host
        elif self.bind_addr not in ("0.0.0.0", "", "::"):
            host = self.bind_addr
        else:
            host = "127.0.0.1"
        return f"http://{host}:{self.bind_port}/sub/{raw_token}"

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
                                       enabled, subscription_token, subscription_token_hash, revision, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 1, ?, ?);
                """, (u_id, nickname, csqtt, qwdtt, snell, mieru, dns, custom, raw_token, tok_hash, now, now))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{nickname}' already exists"}
        except Exception as e:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in normalized_fields.values() if v)
        sub_url = self.get_sub_url(raw_token)
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

            # Проверка OpenFlux v2
            c_of = self.conn.cursor()
            c_of.execute("SELECT enabled FROM user_openflux_config WHERE user_id = ?;", (r["id"],))
            of_row = c_of.fetchone()
            of_en = bool(of_row["enabled"]) if of_row else False
            c_of.execute("SELECT COUNT(*) FROM user_openflux_selection WHERE user_id = ?;", (r["id"],))
            of_cnt = c_of.fetchone()[0] if of_en else 0

            total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list)
            if of_en and of_cnt > 0:
                total_uris += 1

            raw_token = r["subscription_token"] if "subscription_token" in r.keys() and r["subscription_token"] else ""
            sub_url = self.get_sub_url(raw_token)

            users.append({
                "id": r["id"],
                "nickname": r["nickname"],
                "enabled": bool(r["enabled"]),
                "revision": r["revision"],
                "total_uris": total_uris,
                "subscription_url": sub_url,
                "token": raw_token,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
                "protocols": {
                    "csqtt": len(csqtt_list) > 0,
                    "qwdtt": len(qwdtt_list) > 0,
                    "snell": len(snell_list) > 0,
                    "mieru": len(mieru_list) > 0,
                    "masterdnsvpn": len(dns_list) > 0,
                    "custom": len(custom_list) > 0,
                    "openflux": of_en and of_cnt > 0,
                },
                "counts": {
                    "csqtt": len(csqtt_list),
                    "qwdtt": len(qwdtt_list),
                    "snell": len(snell_list),
                    "mieru": len(mieru_list),
                    "masterdnsvpn": len(dns_list),
                    "custom": len(custom_list),
                    "openflux": of_cnt,
                }
            })
        return 200, users

    def get_user(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
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

        # Проверка OpenFlux v2
        c_of = self.conn.cursor()
        c_of.execute("SELECT enabled FROM user_openflux_config WHERE user_id = ?;", (r["id"],))
        of_row = c_of.fetchone()
        of_en = bool(of_row["enabled"]) if of_row else False
        c_of.execute("SELECT COUNT(*) FROM user_openflux_selection WHERE user_id = ?;", (r["id"],))
        of_cnt = c_of.fetchone()[0] if of_en else 0

        total_uris = len(csqtt_list) + len(qwdtt_list) + len(snell_list) + len(mieru_list) + len(dns_list) + len(custom_list)
        if of_en and of_cnt > 0:
            total_uris += 1

        raw_token = r["subscription_token"] if "subscription_token" in r.keys() and r["subscription_token"] else ""
        sub_url = self.get_sub_url(raw_token)

        return 200, {
            "id": r["id"],
            "nickname": r["nickname"],
            "subscription_url": sub_url,
            "token": raw_token,
            "subscription_token": raw_token,
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
            "openflux_enabled": of_en,
            "openflux_groups_count": of_cnt,
            "total_uris": total_uris,
            "enabled": bool(r["enabled"]),
            "revision": r["revision"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"]
        }

    def update_user(self, user_id: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        resolved_id = cur["id"]
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
                      new_enabled, new_revision, now, resolved_id))
        except sqlite3.IntegrityError:
            return 409, {"error": f"User with nickname '{new_nick}' already exists"}
        except Exception:
            return 500, {"error": "Internal database error"}

        total_uris = sum(len(v.splitlines()) for v in updated_fields.values() if v)

        return 200, {
            "id": resolved_id,
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
        user_id = (user_id or "").strip()
        if not user_id:
            return 400, {"error": "User ID or nickname cannot be empty"}
        with self.conn:
            c = self.conn.cursor()
            c.execute("SELECT id FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
            cur = c.fetchone()
            if not cur:
                return 404, {"error": "User not found"}
            resolved_id = cur["id"]
            c.execute("DELETE FROM user_openflux_selection WHERE user_id = ?;", (resolved_id,))
            c.execute("DELETE FROM user_openflux_config WHERE user_id = ?;", (resolved_id,))
            c.execute("DELETE FROM users WHERE id = ?;", (resolved_id,))
            self.conn.commit()
        return 200, {"success": True, "message": f"User '{user_id}' deleted successfully"}

    def rotate_token(self, user_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT id, revision FROM users WHERE id = ? OR nickname = ?;", (user_id, user_id))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "User not found"}

        resolved_id = cur["id"]
        new_raw_token = secrets.token_urlsafe(32)
        new_tok_hash = hash_token(new_raw_token)
        new_rev = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.conn:
            c.execute("""
                UPDATE users
                SET subscription_token = ?, subscription_token_hash = ?, revision = ?, updated_at = ?
                WHERE id = ?;
            """, (new_raw_token, new_tok_hash, new_rev, now, resolved_id))

        sub_url = self.get_sub_url(new_raw_token)
        return 200, {
            "id": resolved_id,
            "subscription_url": sub_url,
            "token": new_raw_token,
            "subscription_token": new_raw_token,
            "revision": new_rev,
            "updated_at": now
        }

    def list_openflux_groups(self) -> tuple[int, list]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups ORDER BY created_at ASC;")
        res = []
        for r in c.fetchall():
            try:
                urls = json.loads(r["urls_json"])
            except Exception:
                urls = []
            res.append({
                "id": r["id"],
                "name": r["name"],
                "mode": r["mode"],
                "transport": r["transport"],
                "urls": urls,
                "codec": r["codec"],
                "encryption_key": r["encryption_key"] or "",
                "source_slot": r["source_slot"],
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            })
        return 200, res

    def get_openflux_group(self, group_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups WHERE id = ? OR name = ?;", (group_id, group_id))
        r = c.fetchone()
        if not r:
            return 404, {"error": "OpenFlux group not found"}
        try:
            urls = json.loads(r["urls_json"])
        except Exception:
            urls = []
        return 200, {
            "id": r["id"],
            "name": r["name"],
            "mode": r["mode"],
            "transport": r["transport"],
            "urls": urls,
            "codec": r["codec"],
            "encryption_key": r["encryption_key"] or "",
            "source_slot": r["source_slot"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def create_openflux_group(self, data: dict) -> tuple[int, dict]:
        name = str(data.get("name") or "").strip()
        if not name or len(name) > 64:
            return 400, {"error": "Group name is required and must be between 1 and 64 characters"}

        mode = str(data.get("mode") or "classic").strip().lower()
        if mode not in ALLOWED_OPENFLUX_MODES:
            return 400, {"error": f"Invalid mode '{mode}'. Allowed: {', '.join(sorted(ALLOWED_OPENFLUX_MODES))}"}

        transport = str(data.get("transport") or "").strip().lower()
        if transport not in ALLOWED_OPENFLUX_TRANSPORTS:
            return 400, {"error": f"Invalid transport '{transport}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}"}

        codec = str(data.get("codec") or "legacy").strip().lower()
        if codec not in ALLOWED_OPENFLUX_CODECS:
            return 400, {"error": f"Invalid codec '{codec}'. Allowed: {', '.join(sorted(ALLOWED_OPENFLUX_CODECS))}"}

        raw_urls = data.get("urls")
        urls = []
        if isinstance(raw_urls, str):
            for line in raw_urls.splitlines():
                s = line.strip()
                if s:
                    urls.append(s)
        elif isinstance(raw_urls, list):
            for item in raw_urls:
                if isinstance(item, str):
                    s = item.strip()
                    if s:
                        urls.append(s)
                else:
                    return 400, {"error": "All URLs must be strings"}
        else:
            return 400, {"error": "Field 'urls' must be a string or list of strings"}

        if mode == "classic" and len(urls) != 1:
            return 400, {"error": f"Classic mode requires exactly 1 URL (provided: {len(urls)})"}
        if mode == "multistream" and not (1 <= len(urls) <= 4):
            return 400, {"error": f"Multistream mode requires 1 to 4 URLs (provided: {len(urls)})"}

        seen_u = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u)
            if not ok_u:
                return 400, {"error": f"Invalid URL '{u}': {err_u}"}
            if u in seen_u:
                return 400, {"error": f"Duplicate URL in group: '{u}'"}
            seen_u.add(u)

        encryption_key = str(data.get("encryption_key") or "").strip()
        source_slot = data.get("source_slot")
        if source_slot is not None:
            try:
                source_slot = int(source_slot)
                if not (1 <= source_slot <= 8):
                    source_slot = None
            except Exception:
                source_slot = None

        group_id = str(data.get("id") or "").strip()
        if not group_id:
            group_id = str(uuid.uuid4())
        else:
            try:
                uuid.UUID(group_id)
            except Exception:
                return 400, {"error": f"Invalid group ID format (must be valid UUID): '{group_id}'"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                c = self.conn.cursor()
                c.execute("""
                    INSERT INTO openflux_groups (id, name, mode, transport, urls_json, codec, encryption_key, source_slot, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (group_id, name, mode, transport, json.dumps(urls), codec, encryption_key, source_slot, now, now))
        except sqlite3.IntegrityError:
            return 409, {"error": f"OpenFlux group with ID '{group_id}' already exists"}
        except Exception as e:
            return 500, {"error": f"Internal database error: {e}"}

        return 201, {
            "id": group_id,
            "name": name,
            "mode": mode,
            "transport": transport,
            "urls": urls,
            "codec": codec,
            "encryption_key": encryption_key,
            "source_slot": source_slot,
            "created_at": now,
            "updated_at": now,
        }

    def update_openflux_group(self, group_id: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM openflux_groups WHERE id = ?;", (group_id,))
        cur = c.fetchone()
        if not cur:
            return 404, {"error": "OpenFlux group not found"}

        name = cur["name"]
        if "name" in data:
            candidate_name = str(data["name"]).strip()
            if not candidate_name or len(candidate_name) > 64:
                return 400, {"error": "Group name must be between 1 and 64 characters"}
            name = candidate_name

        mode = cur["mode"]
        if "mode" in data:
            candidate_mode = str(data["mode"]).strip().lower()
            if candidate_mode not in ALLOWED_OPENFLUX_MODES:
                return 400, {"error": f"Invalid mode '{candidate_mode}'"}
            mode = candidate_mode

        transport = cur["transport"]
        if "transport" in data:
            candidate_transport = str(data["transport"]).strip().lower()
            if candidate_transport not in ALLOWED_OPENFLUX_TRANSPORTS:
                return 400, {"error": f"Invalid transport '{candidate_transport}'. Allowed in v2: {', '.join(sorted(ALLOWED_OPENFLUX_TRANSPORTS))}"}
            transport = candidate_transport

        codec = cur["codec"]
        if "codec" in data:
            candidate_codec = str(data["codec"]).strip().lower()
            if candidate_codec not in ALLOWED_OPENFLUX_CODECS:
                return 400, {"error": f"Invalid codec '{candidate_codec}'"}
            codec = candidate_codec

        encryption_key = cur["encryption_key"]
        if "encryption_key" in data:
            encryption_key = str(data["encryption_key"]).strip()

        source_slot = cur["source_slot"]
        if "source_slot" in data:
            val = data["source_slot"]
            if val is not None:
                try:
                    source_slot = int(val)
                except Exception:
                    pass
            else:
                source_slot = None

        if "urls" in data:
            raw_urls = data["urls"]
            urls = []
            if isinstance(raw_urls, str):
                for line in raw_urls.splitlines():
                    s = line.strip()
                    if s:
                        urls.append(s)
            elif isinstance(raw_urls, list):
                for item in raw_urls:
                    if isinstance(item, str):
                        s = item.strip()
                        if s:
                            urls.append(s)
                    else:
                        return 400, {"error": "All URLs must be strings"}
            else:
                return 400, {"error": "Field 'urls' must be a string or list of strings"}
        else:
            try:
                urls = json.loads(cur["urls_json"])
            except Exception:
                urls = []

        if mode == "classic" and len(urls) != 1:
            return 400, {"error": f"Classic mode requires exactly 1 URL (provided: {len(urls)})"}
        if mode == "multistream" and not (1 <= len(urls) <= 4):
            return 400, {"error": f"Multistream mode requires 1 to 4 URLs (provided: {len(urls)})"}

        seen_u = set()
        for u in urls:
            ok_u, err_u = validate_openflux_url(u)
            if not ok_u:
                return 400, {"error": f"Invalid URL '{u}': {err_u}"}
            if u in seen_u:
                return 400, {"error": f"Duplicate URL in group: '{u}'"}
            seen_u.add(u)

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                c.execute("""
                    UPDATE openflux_groups
                    SET name = ?, mode = ?, transport = ?, urls_json = ?, codec = ?,
                        encryption_key = ?, source_slot = ?, updated_at = ?
                    WHERE id = ?;
                """, (name, mode, transport, json.dumps(urls), codec, encryption_key, source_slot, now, group_id))

                # Автоматический инкремент ревизии для всех пользователей, выбравших эту группу
                c.execute("SELECT DISTINCT user_id FROM user_openflux_selection WHERE group_id = ?;", (group_id,))
                affected_users = [row[0] for row in c.fetchall()]
                for u_id in affected_users:
                    c.execute("""
                        UPDATE user_openflux_config
                        SET revision = revision + 1, updated_at = ?
                        WHERE user_id = ?;
                    """, (now, u_id))
                    c.execute("""
                        UPDATE users
                        SET revision = revision + 1, updated_at = ?
                        WHERE id = ?;
                    """, (now, u_id))
        except Exception as e:
            return 500, {"error": f"Database update error: {e}"}

        return 200, {
            "id": group_id,
            "name": name,
            "mode": mode,
            "transport": transport,
            "urls": urls,
            "codec": codec,
            "encryption_key": encryption_key,
            "source_slot": source_slot,
            "created_at": cur["created_at"],
            "updated_at": now,
        }

    def delete_openflux_group(self, group_id: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT id FROM openflux_groups WHERE id = ?;", (group_id,))
        if not c.fetchone():
            return 404, {"error": "OpenFlux group not found"}

        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        try:
            with self.conn:
                c.execute("SELECT DISTINCT user_id FROM user_openflux_selection WHERE group_id = ?;", (group_id,))
                affected_users = [row[0] for row in c.fetchall()]

                c.execute("DELETE FROM openflux_groups WHERE id = ?;", (group_id,))
                c.execute("DELETE FROM user_openflux_selection WHERE group_id = ?;", (group_id,))

                for u_id in affected_users:
                    c.execute("""
                        UPDATE user_openflux_config
                        SET revision = revision + 1, updated_at = ?
                        WHERE user_id = ?;
                    """, (now, u_id))
                    c.execute("""
                        UPDATE users
                        SET revision = revision + 1, updated_at = ?
                        WHERE id = ?;
                    """, (now, u_id))
                    c.execute("SELECT group_id FROM user_openflux_selection WHERE user_id = ? ORDER BY position ASC;", (u_id,))
                    remaining = [row[0] for row in c.fetchall()]
                    for pos, gid in enumerate(remaining):
                        c.execute("UPDATE user_openflux_selection SET position = ? WHERE user_id = ? AND group_id = ?;", (pos, u_id, gid))
        except Exception as e:
            return 500, {"error": f"Database delete error: {e}"}

        return 200, {"success": True, "message": f"OpenFlux group '{group_id}' deleted successfully"}

    def get_user_openflux(self, user_id_or_nick: str) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
        of_cfg = c.fetchone()

        if not of_cfg:
            stable_conn_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.conn:
                self.conn.execute("""
                    INSERT INTO user_openflux_config (user_id, enabled, connection_id, name, mode, balancer_strategy, revision, updated_at)
                    VALUES (?, 0, ?, ?, 'classic', 'roundRobin', 1, ?);
                """, (u_id, stable_conn_id, f"TUNA-{user['nickname']}", now))
            c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
            of_cfg = c.fetchone()

        c.execute("""
            SELECT g.* FROM user_openflux_selection s
            JOIN openflux_groups g ON s.group_id = g.id
            WHERE s.user_id = ?
            ORDER BY s.position ASC;
        """, (u_id,))
        sel_groups = c.fetchall()

        groups_res = []
        group_ids = []
        total_urls = 0
        for g in sel_groups:
            try:
                urls = json.loads(g["urls_json"])
            except Exception:
                urls = []
            group_ids.append(g["id"])
            total_urls += len(urls)
            groups_res.append({
                "id": g["id"],
                "name": g["name"],
                "mode": g["mode"],
                "transport": g["transport"],
                "urls": urls,
                "codec": g["codec"],
                "encryption_key": g["encryption_key"] or "",
                "source_slot": g["source_slot"],
                "created_at": g["created_at"],
                "updated_at": g["updated_at"],
            })

        v2_uri = ""
        if of_cfg["enabled"] and 1 <= len(groups_res) <= 8:
            bundle_dict = {
                "schema": "openflux-bundle",
                "version": 2,
                "issuer_id": self.issuer_id,
                "id": of_cfg["connection_id"],
                "revision": int(of_cfg["revision"]),
                "name": of_cfg["name"],
                "mode": of_cfg["mode"],
                "balancer_strategy": of_cfg["balancer_strategy"],
                "groups": [
                    {
                        "id": gr["id"],
                        "name": gr["name"],
                        "mode": gr["mode"],
                        "transport": gr["transport"],
                        "urls": gr["urls"],
                        "codec": gr["codec"],
                        "encryption_key": gr["encryption_key"]
                    }
                    for gr in groups_res
                ],
            }
            ok_ser, _, uri_res = serialize_openflux_v2_bundle(bundle_dict)
            if ok_ser:
                v2_uri = uri_res

        return 200, {
            "user_id": u_id,
            "nickname": user["nickname"],
            "enabled": bool(of_cfg["enabled"]),
            "connection_id": of_cfg["connection_id"],
            "name": of_cfg["name"],
            "mode": of_cfg["mode"],
            "balancer_strategy": of_cfg["balancer_strategy"],
            "revision": of_cfg["revision"],
            "group_ids": group_ids,
            "groups": groups_res,
            "total_groups": len(groups_res),
            "total_urls": total_urls,
            "v2_uri": v2_uri,
            "updated_at": of_cfg["updated_at"],
        }

    def update_user_openflux(self, user_id_or_nick: str, data: dict) -> tuple[int, dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ? OR nickname = ?;", (user_id_or_nick, user_id_or_nick))
        user = c.fetchone()
        if not user:
            return 404, {"error": "User not found"}

        u_id = user["id"]
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
        cur = c.fetchone()
        if not cur:
            stable_conn_id = str(uuid.uuid4())
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.conn:
                self.conn.execute("""
                    INSERT INTO user_openflux_config (user_id, enabled, connection_id, name, mode, balancer_strategy, revision, updated_at)
                    VALUES (?, 0, ?, ?, 'classic', 'roundRobin', 1, ?);
                """, (u_id, stable_conn_id, f"TUNA-{user['nickname']}", now))
            c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (u_id,))
            cur = c.fetchone()

        new_enabled = cur["enabled"]
        if "enabled" in data:
            new_enabled = 1 if data["enabled"] else 0

        name = cur["name"]
        if "name" in data:
            candidate_name = str(data["name"]).strip()
            if not candidate_name or len(candidate_name) > 64:
                return 400, {"error": "Connection name must be between 1 and 64 characters"}
            name = candidate_name

        mode = cur["mode"]
        if "mode" in data:
            candidate_mode = str(data["mode"]).strip().lower()
            if candidate_mode not in ALLOWED_OPENFLUX_MODES:
                return 400, {"error": f"Invalid mode '{candidate_mode}'"}
            mode = candidate_mode

        balancer_strategy = cur["balancer_strategy"]
        if "balancer_strategy" in data:
            candidate_strat = str(data["balancer_strategy"]).strip()
            if candidate_strat not in ALLOWED_BALANCER_STRATEGIES:
                return 400, {"error": f"Invalid balancer_strategy '{candidate_strat}'. Allowed: {', '.join(sorted(ALLOWED_BALANCER_STRATEGIES))}"}
            balancer_strategy = candidate_strat

        if "group_ids" in data:
            raw_gids = data["group_ids"]
            if not isinstance(raw_gids, list):
                return 400, {"error": "Field 'group_ids' must be a list of group IDs"}
            group_ids = [str(gid).strip() for gid in raw_gids if str(gid).strip()]
        else:
            c.execute("SELECT group_id FROM user_openflux_selection WHERE user_id = ? ORDER BY position ASC;", (u_id,))
            group_ids = [r[0] for r in c.fetchall()]

        if len(group_ids) != len(set(group_ids)):
            return 400, {"error": "Duplicate group IDs in selection are not allowed"}

        if new_enabled:
            if not (1 <= len(group_ids) <= 8):
                return 400, {"error": f"Active OpenFlux bundle requires between 1 and 8 groups (provided: {len(group_ids)})"}

        groups_to_attach = []
        total_bundle_urls = 0
        for gid in group_ids:
            c.execute("SELECT * FROM openflux_groups WHERE id = ?;", (gid,))
            g = c.fetchone()
            if not g:
                return 400, {"error": f"Referenced OpenFlux group '{gid}' does not exist"}
            try:
                g_urls = json.loads(g["urls_json"])
            except Exception:
                g_urls = []
            if g["transport"] not in ALLOWED_OPENFLUX_TRANSPORTS:
                return 400, {"error": f"Group '{g['name']}' has forbidden transport '{g['transport']}'"}
            if new_enabled:
                if mode == "classic" and (len(g_urls) != 1 or g["mode"] != "classic"):
                    return 400, {"error": f"Bundle mode is classic, but group '{g['name']}' is {g['mode']} with {len(g_urls)} URLs (must be classic with 1 URL)"}
                if mode == "multistream" and (not (1 <= len(g_urls) <= 4) or g["mode"] != "multistream"):
                    return 400, {"error": f"Bundle mode is multistream, but group '{g['name']}' is {g['mode']} with {len(g_urls)} URLs (must be multistream with 1..4 URLs)"}
            total_bundle_urls += len(g_urls)
            groups_to_attach.append(g)

        if new_enabled and total_bundle_urls > 32:
            return 400, {"error": f"Total URLs across bundle groups exceeds 32 (got {total_bundle_urls})"}

        new_rev = cur["revision"] + 1
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        try:
            with self.conn:
                c.execute("""
                    UPDATE user_openflux_config
                    SET enabled = ?, name = ?, mode = ?, balancer_strategy = ?, revision = ?, updated_at = ?
                    WHERE user_id = ?;
                """, (new_enabled, name, mode, balancer_strategy, new_rev, now, u_id))

                c.execute("DELETE FROM user_openflux_selection WHERE user_id = ?;", (u_id,))
                for pos, gid in enumerate(group_ids):
                    c.execute("""
                        INSERT INTO user_openflux_selection (user_id, group_id, position)
                        VALUES (?, ?, ?);
                    """, (u_id, gid, pos))

                c.execute("""
                    UPDATE users
                    SET revision = revision + 1, updated_at = ?
                    WHERE id = ?;
                """, (now, u_id))
        except Exception as e:
            return 500, {"error": f"Database error updating OpenFlux user config: {e}"}

        return self.get_user_openflux(u_id)

    def import_local_openflux_groups(self, instances_dir: str = "/etc/openflux/instances", pool_mode_file: str = "/etc/openflux/pool.mode") -> tuple[int, dict]:
        """
        Безопасный импорт локально настроенных инстансов OpenFlux (слоты 1..8) в каталог БД.
        Парсинг без eval/source/sh.
        """
        pool_mode = "classic"
        if os.path.isfile(pool_mode_file):
            try:
                with open(pool_mode_file, "r", encoding="utf-8") as f:
                    content = f.read().strip().lower()
                    if content in ALLOWED_OPENFLUX_MODES:
                        pool_mode = content
            except Exception:
                pass

        if not os.path.isdir(instances_dir):
            return 404, {"error": f"Instances directory '{instances_dir}' not found", "imported_count": 0, "groups": []}

        imported_groups = []
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()

        for slot in range(1, 9):
            env_path = os.path.join(instances_dir, f"{slot}.env")
            if not os.path.isfile(env_path):
                continue

            props = {}
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f.read().splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        props[k] = v
            except Exception:
                continue

            url_raw = props.get("URL", "").strip()
            if not url_raw:
                continue

            urls = []
            for u in re.split(r"[\s\r\n]+", url_raw):
                u_str = u.strip()
                if u_str and u_str.startswith("https://"):
                    urls.append(u_str)

            if not urls:
                continue

            transport = props.get("TRANSPORT", "mailru").strip().lower()
            if transport not in ALLOWED_OPENFLUX_TRANSPORTS:
                continue

            codec = props.get("CODEC", "legacy").strip().lower()
            if codec not in ALLOWED_OPENFLUX_CODECS:
                codec = "legacy"

            enc_key = props.get("ENCRYPTION_KEY", "").strip()
            slot_mode = props.get("POOL_MODE", pool_mode).strip().lower()
            if slot_mode not in ALLOWED_OPENFLUX_MODES:
                slot_mode = pool_mode

            if slot_mode == "classic":
                urls = [urls[0]]
            elif slot_mode == "multistream":
                urls = urls[:4]

            c = self.conn.cursor()
            c.execute("SELECT id FROM openflux_groups WHERE source_slot = ?;", (slot,))
            existing = c.fetchone()
            if existing:
                grp_id = existing["id"]
                name = f"OF-Slot-{slot}"
                with self.conn:
                    self.conn.execute("""
                        UPDATE openflux_groups
                        SET name = ?, mode = ?, transport = ?, urls_json = ?, codec = ?,
                            encryption_key = ?, updated_at = ?
                        WHERE id = ?;
                    """, (name, slot_mode, transport, json.dumps(urls), codec, enc_key, now, grp_id))
            else:
                grp_id = str(uuid.uuid4())
                name = f"OF-Slot-{slot}"
                with self.conn:
                    self.conn.execute("""
                        INSERT INTO openflux_groups (id, name, mode, transport, urls_json, codec, encryption_key, source_slot, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """, (grp_id, name, slot_mode, transport, json.dumps(urls), codec, enc_key, slot, now, now))

            imported_groups.append({
                "id": grp_id,
                "name": name,
                "slot": slot,
                "mode": slot_mode,
                "transport": transport,
                "urls": urls,
                "codec": codec,
            })

        return 200, {
            "success": True,
            "pool_mode": pool_mode,
            "imported_count": len(imported_groups),
            "groups": imported_groups
        }

    def get_subscription_payload(self, token: str, if_none_match: str = None) -> tuple[int, dict, bytes]:
        """
        Выдача подписки по токену:
        - Поиск по SHA256(token).
        - Все протоколы в строгом порядке: CSQTT -> WDTT -> Snell -> Mieru -> MasterDNS -> Custom.
        - OpenFlux v2: если включен в user_openflux_config и содержит 1-8 валидных групп,
          добавляется ровно одна строка openflux-bundle://v2/<Base64URL-NoPadding>.
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

        # OpenFlux v2 интеграция
        c.execute("SELECT * FROM user_openflux_config WHERE user_id = ?;", (user["id"],))
        of_cfg = c.fetchone()
        if of_cfg and of_cfg["enabled"]:
            c.execute("""
                SELECT g.* FROM user_openflux_selection s
                JOIN openflux_groups g ON s.group_id = g.id
                WHERE s.user_id = ?
                ORDER BY s.position ASC;
            """, (user["id"],))
            selected_groups = c.fetchall()
            if 1 <= len(selected_groups) <= 8:
                groups_payload = []
                total_of_urls = 0
                valid_bundle = True
                for g in selected_groups:
                    try:
                        urls = json.loads(g["urls_json"])
                    except Exception:
                        urls = []
                    if not isinstance(urls, list) or not urls:
                        valid_bundle = False
                        break
                    if of_cfg["mode"] == "classic" and (len(urls) != 1 or g["mode"] != "classic"):
                        valid_bundle = False
                        break
                    if of_cfg["mode"] == "multistream" and (not (1 <= len(urls) <= 4) or g["mode"] != "multistream"):
                        valid_bundle = False
                        break
                    if g["transport"] not in ALLOWED_OPENFLUX_TRANSPORTS:
                        valid_bundle = False
                        break
                    total_of_urls += len(urls)
                    groups_payload.append({
                        "id": g["id"],
                        "name": g["name"],
                        "mode": g["mode"],
                        "transport": g["transport"],
                        "urls": urls,
                        "codec": g["codec"],
                        "encryption_key": g["encryption_key"] or "",
                    })
                if valid_bundle and 1 <= len(groups_payload) <= 8 and total_of_urls <= 32:
                    issuer_id = self.issuer_id
                    bundle_dict = {
                        "schema": "openflux-bundle",
                        "version": 2,
                        "issuer_id": issuer_id,
                        "id": of_cfg["connection_id"],
                        "revision": int(of_cfg["revision"]),
                        "name": of_cfg["name"],
                        "mode": of_cfg["mode"],
                        "balancer_strategy": of_cfg["balancer_strategy"],
                        "groups": groups_payload,
                    }
                    ok_ser, _, v2_uri = serialize_openflux_v2_bundle(bundle_dict)
                    if ok_ser and v2_uri:
                        non_empty.append(v2_uri)

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

        # OpenFlux groups catalog: GET /api/openflux/groups
        if path == "/api/openflux/groups":
            status, res = self.app.list_openflux_groups()
            self.send_json(status, res)
            return

        # GET /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            status, res = self.app.get_openflux_group(group_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/openflux
        m_of_user = re.match(r"^/api/users/([^/]+)/openflux$", path)
        if m_of_user:
            user_id = unquote(m_of_user.group(1))
            status, res = self.app.get_user_openflux(user_id)
            self.send_json(status, res)
            return

        # Управляющий API: GET /api/users
        if path == "/api/users":
            status, res = self.app.list_users()
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1))
            status, res = self.app.get_user(user_id)
            self.send_json(status, res)
            return

        # GET /api/users/<id_or_nickname>/subscription-url
        m_sub_url = re.match(r"^/api/users/([^/]+)/subscription-url$", path)
        if m_sub_url:
            user_id = unquote(m_sub_url.group(1))
            status, res = self.app.get_user(user_id)
            if status != 200:
                self.send_json(status, res)
                return
            self.send_json(200, {
                "id": res["id"],
                "nickname": res["nickname"],
                "token": res.get("token", ""),
                "subscription_url": res.get("subscription_url", ""),
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

        # POST /api/openflux/groups
        if path == "/api/openflux/groups":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.create_openflux_group(data)
            self.send_json(status, res)
            return

        # POST /api/openflux/import-local
        if path == "/api/openflux/import-local":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            instances_dir = str(data.get("instances_dir") or "/etc/openflux/instances")
            pool_mode_file = str(data.get("pool_mode_file") or "/etc/openflux/pool.mode")
            status, res = self.app.import_local_openflux_groups(instances_dir, pool_mode_file)
            self.send_json(status, res)
            return

        # POST /api/users
        if path == "/api/users":
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.create_user(data)
            self.send_json(status, res)
            return

        # POST /api/users/<id_or_nickname>/rotate-token
        m_rotate = re.match(r"^/api/users/([^/]+)/rotate-token$", path)
        if m_rotate:
            user_id = unquote(m_rotate.group(1))
            status, res = self.app.rotate_token(user_id)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_PUT(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # PUT /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_openflux_group(group_id, data)
            self.send_json(status, res)
            return

        # PUT /api/users/<id_or_nickname>/openflux
        m_of_user = re.match(r"^/api/users/([^/]+)/openflux$", path)
        if m_of_user:
            user_id = unquote(m_of_user.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_user_openflux(user_id, data)
            self.send_json(status, res)
            return

        # PUT /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1))
            try:
                data = self.read_json_body()
            except ValueError as e:
                code = 413 if "Payload Too Large" in str(e) else 400
                self.send_json(code, {"error": str(e)})
                return
            status, res = self.app.update_user(user_id, data)
            self.send_json(status, res)
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # DELETE /api/openflux/groups/<id>
        m_of_grp = re.match(r"^/api/openflux/groups/([^/]+)$", path)
        if m_of_grp:
            group_id = unquote(m_of_grp.group(1))
            status, res = self.app.delete_openflux_group(group_id)
            self.send_json(status, res)
            return

        # DELETE /api/users/<id_or_nickname>
        m_user = re.match(r"^/api/users/([^/]+)$", path)
        if m_user:
            user_id = unquote(m_user.group(1)).strip()
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
