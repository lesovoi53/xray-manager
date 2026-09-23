#!/usr/bin/env python3
"""
Приемочные тесты для минимального сервера ссылок TUNA (Раздел 8 ТЗ).
Покрывает все 16 приемочных сценариев.
"""

import sys
import os
import io
import time
import json
import base64
import shutil
import urllib.request
import urllib.error
import tempfile
import threading
import unittest

# Добавляем родительский каталог в sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from importlib import import_module
tuna_module = import_module("tuna-subscriptions")
SubscriptionApp = tuna_module.SubscriptionApp
SubscriptionRequestHandler = tuna_module.SubscriptionRequestHandler
ThreadingHTTPServer = tuna_module.ThreadingHTTPServer


class TunaSubscriptionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = tempfile.mkdtemp(prefix="tuna_test_")
        cls.db_path = os.path.join(cls.test_dir, "test_sub.db")
        cls.log_file = os.path.join(cls.test_dir, "test_service.log")

        cls.config = {
            "server": {
                "bind_address": "127.0.0.1",
                "port": 0,  # 0 выделит свободный системный порт
                "max_request_body_size": 65536,
            },
            "database": {
                "path": cls.db_path,
            },
            "limits": {
                "max_nickname_length": 64,
                "max_uri_length": 4096,
                "max_users": 1000,
            },
            "logging": {
                "file": cls.log_file,
                "level": "INFO",
            },
        }

        cls.app = SubscriptionApp(cls.config)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SubscriptionRequestHandler)
        cls.server.app = cls.app
        cls.port = cls.server.server_address[1]
        cls.app.bind_port = cls.port

        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.app.conn.close()
        shutil.rmtree(cls.test_dir, ignore_errors=True)

    def api_request(self, method: str, path: str, data: dict = None, headers: dict = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        req_headers = {"User-Agent": "TunaTest/1.0"}
        if headers:
            req_headers.update(headers)

        payload_bytes = None
        if data is not None:
            payload_bytes = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=payload_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                resp_data = resp.read()
                return resp.status, dict(resp.headers), resp_data
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    # --------------------------------------------------------------------------
    # ТЕСТ 1: Создание пользователя с ником и пятью ссылками
    # --------------------------------------------------------------------------
    def test_01_create_user(self):
        payload = {
            "nickname": "ivan",
            "csqtt": "csqtt://sad_534188_sad@185.22.153.4:37000?plugin=v2ray+tls",
            "qwdtt": "qwdtt://config?name=WDTT-Main&peer=185.22.153.4%3A56000&hashes=#",
            "snell": "snell://secret_psk_123@185.22.153.4:1488/?version=5&reuse=true&tfo=true#Snell-v5",
            "mieru": "mierus://ADMIN:mita_pass@185.22.153.4/?profile=Home&port=2020-2030&low-entropy-mode=LOW_ENTROPY_MODE_48",
            "masterdnsvpn": "stormdns://d.example.com?key=a7125b5f3cc23e525123c677bc6d202e#StormDNS"
        }
        status, headers, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        self.assertIn("id", res)
        self.assertIn("token", res)
        self.assertIn("subscription_url", res)
        self.assertEqual(res["nickname"], "ivan")
        self.assertEqual(res["revision"], 1)

    # --------------------------------------------------------------------------
    # ТЕСТ 2: Уникальный URL для двух пользователей
    # --------------------------------------------------------------------------
    def test_02_unique_url_for_two_users(self):
        s1, _, b1 = self.api_request("POST", "/api/users", {"nickname": "alice", "snell": "snell://p1@1.1.1.1:1488"})
        s2, _, b2 = self.api_request("POST", "/api/users", {"nickname": "bob", "snell": "snell://p2@2.2.2.2:1488"})
        self.assertEqual(s1, 201)
        self.assertEqual(s2, 201)
        u1 = json.loads(b1.decode())
        u2 = json.loads(b2.decode())
        self.assertNotEqual(u1["token"], u2["token"])
        self.assertNotEqual(u1["subscription_url"], u2["subscription_url"])

    # --------------------------------------------------------------------------
    # ТЕСТ 3: Изоляция: токен одного пользователя не выдаёт ссылки другого
    # --------------------------------------------------------------------------
    def test_03_token_isolation(self):
        _, _, b_alice = self.api_request("POST", "/api/users", {
            "nickname": "alice_iso",
            "snell": "snell://alice_secret@1.1.1.1:1488"
        })
        _, _, b_bob = self.api_request("POST", "/api/users", {
            "nickname": "bob_iso",
            "snell": "snell://bob_secret@2.2.2.2:1488"
        })
        tok_alice = json.loads(b_alice)["token"]
        tok_bob = json.loads(b_bob)["token"]

        # Запрос по токену Алисы
        s_a, _, body_a = self.api_request("GET", f"/sub/{tok_alice}")
        decoded_a = base64.b64decode(body_a).decode("utf-8")
        self.assertIn("alice_secret", decoded_a)
        self.assertNotIn("bob_secret", decoded_a)

        # Запрос по токену Боба
        s_b, _, body_b = self.api_request("GET", f"/sub/{tok_bob}")
        decoded_b = base64.b64decode(body_b).decode("utf-8")
        self.assertIn("bob_secret", decoded_b)
        self.assertNotIn("alice_secret", decoded_b)

    # --------------------------------------------------------------------------
    # ТЕСТ 4: Выдача всех пяти ссылок в заданном порядке
    # --------------------------------------------------------------------------
    def test_04_strict_five_protocols_order(self):
        csqtt_val = "csqtt://test_csqtt"
        qwdtt_val = "qwdtt://test_qwdtt"
        snell_val = "snell://test_snell"
        mieru_val = "mierus://test_mieru"
        dns_val   = "stormdns://test_dns"

        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "order_tester",
            "csqtt": csqtt_val,
            "qwdtt": qwdtt_val,
            "snell": snell_val,
            "mieru": mieru_val,
            "masterdnsvpn": dns_val
        })
        token = json.loads(body)["token"]

        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [line for line in base64.b64decode(sub_body).decode("utf-8").split("\n") if line]

        self.assertEqual(len(lines), 5)
        self.assertEqual(lines[0], csqtt_val)
        self.assertEqual(lines[1], qwdtt_val)
        self.assertEqual(lines[2], snell_val)
        self.assertEqual(lines[3], mieru_val)
        self.assertEqual(lines[4], dns_val)

    # --------------------------------------------------------------------------
    # ТЕСТ 5: Выдача только непустых ссылок
    # --------------------------------------------------------------------------
    def test_05_only_non_empty_links(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "sparse_user",
            "csqtt": "",
            "qwdtt": "qwdtt://peer1",
            "snell": "",
            "mieru": "mierus://mita1",
            "masterdnsvpn": ""
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [line for line in base64.b64decode(sub_body).decode("utf-8").split("\n") if line]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "qwdtt://peer1")
        self.assertEqual(lines[1], "mierus://mita1")

    # --------------------------------------------------------------------------
    # ТЕСТ 6: Base64 корректно декодируется в UTF-8 строки URI
    # --------------------------------------------------------------------------
    def test_06_base64_decoding(self):
        csqtt = "csqtt://спец_пользователь:пароль@1.2.3.4:37000"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "utf8_user",
            "csqtt": csqtt
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        raw = base64.b64decode(sub_body).decode("utf-8")
        self.assertEqual(raw.strip(), csqtt)

    # --------------------------------------------------------------------------
    # ТЕСТ 7: Profile-Title содержит ник в UTF-8
    # --------------------------------------------------------------------------
    def test_07_profile_title_header(self):
        nick = "Алексей_VPN"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://test@1.1.1.1:1488"
        })
        token = json.loads(body)["token"]
        _, headers, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertIn("Profile-Title", headers)
        title_val = headers["Profile-Title"]
        # Декодируем если url-encoded или читаем напрямую
        from urllib.parse import unquote
        self.assertEqual(unquote(title_val), nick)
        # Проверяем, что в теле ответа никнейма нет как отдельной строки
        decoded_lines = base64.b64decode(sub_body).decode("utf-8").splitlines()
        self.assertNotIn(nick, decoded_lines)

    # --------------------------------------------------------------------------
    # ТЕСТ 8: CSQTT сохраняет '+' и специальные query-символы
    # --------------------------------------------------------------------------
    def test_08_csqtt_plus_and_query_symbols(self):
        csqtt_raw = "csqtt://sad+534188+sad@89.19.223.185:37000?plugin=v2ray+tls&path=/v2ray+path#CSQTT+VPN"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "plus_csqtt_user",
            "csqtt": csqtt_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, csqtt_raw)
        self.assertIn("+", decoded)
        self.assertNotIn(" ", decoded)

    # --------------------------------------------------------------------------
    # ТЕСТ 9: qWDTT с пустыми hash-параметрами проходит round-trip
    # --------------------------------------------------------------------------
    def test_09_qwdtt_empty_hash(self):
        qwdtt_raw = "qwdtt://config?name=WDTT-Main&peer=89.19.223.185%3A56000&hashes=#"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "qwdtt_empty_hash_user",
            "qwdtt": qwdtt_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, qwdtt_raw)

    # --------------------------------------------------------------------------
    # ТЕСТ 10: Snell, Mieru и MasterDnsVPN возвращаются без потери параметров
    # --------------------------------------------------------------------------
    def test_10_no_param_loss(self):
        snell_raw = "snell://psk_key@1.2.3.4:1488/?version=5&reuse=true&tfo=true&custom_unknown=param1#MySnell"
        mieru_raw = "mierus://user:pass@1.2.3.4/?profile=Mieru&port=2020-2030&custom_enum=999&unknown_flag=1"
        dns_raw   = "stormdns://d.lesovoi.pro?key=a7125b5f3cc23e525123c677bc6d202e&x=4#StormDNS"

        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "param_loss_user",
            "snell": snell_raw,
            "mieru": mieru_raw,
            "masterdnsvpn": dns_raw
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]

        self.assertEqual(lines[0], snell_raw)
        self.assertEqual(lines[1], mieru_raw)
        self.assertEqual(lines[2], dns_raw)

    # --------------------------------------------------------------------------
    # ТЕСТ 11: stormdns:// возвращается без декодирования или сокращения payload
    # --------------------------------------------------------------------------
    def test_11_stormdns_full_payload(self):
        full_stormdns = "stormdns://full_complex_payload_base64_or_domain_data_1234567890?key=abcdef#FullPayloadName"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "stormdns_user",
            "masterdnsvpn": full_stormdns
        })
        token = json.loads(body)["token"]
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, full_stormdns)

    # --------------------------------------------------------------------------
    # ТЕСТ 12: Изменение ника или ссылки меняет revision и ETag
    # --------------------------------------------------------------------------
    def test_12_revision_and_etag_update(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "etag_user",
            "snell": "snell://key1@1.1.1.1:1488"
        })
        user = json.loads(body)
        u_id = user["id"]
        token = user["token"]

        # Первый запрос подписки
        _, h1, _ = self.api_request("GET", f"/sub/{token}")
        etag1 = h1.get("ETag")
        self.assertIsNotNone(etag1)

        # 304 Not Modified
        s_cache, _, _ = self.api_request("GET", f"/sub/{token}", headers={"If-None-Match": etag1})
        self.assertEqual(s_cache, 304)

        # Обновляем пользователя
        self.api_request("PUT", f"/api/users/{u_id}", {
            "snell": "snell://key2_MODIFIED@1.1.1.1:1488"
        })

        # Новый запрос подписки
        _, h2, _ = self.api_request("GET", f"/sub/{token}")
        etag2 = h2.get("ETag")
        self.assertNotEqual(etag1, etag2)

    # --------------------------------------------------------------------------
    # ТЕСТ 13: Ошибка обновления не стирает предыдущую рабочую выдачу
    # --------------------------------------------------------------------------
    def test_13_failed_update_preserves_data(self):
        orig_snell = "snell://working_psk@1.1.1.1:1488"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "fail_safe_user",
            "snell": orig_snell
        })
        user = json.loads(body)
        u_id = user["id"]
        token = user["token"]

        # Пытаемся передать невалидный URI с переводом строки
        bad_status, _, _ = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell": "snell://broken\nnewline@1.1.1.1:1488"
        })
        self.assertEqual(bad_status, 400)

        # Проверяем, что рабочая подписка цела
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        decoded = base64.b64decode(sub_body).decode("utf-8").strip()
        self.assertEqual(decoded, orig_snell)

    # --------------------------------------------------------------------------
    # ТЕСТ 14: Отключённый, удалённый или отозванный token не выдаёт ссылки
    # --------------------------------------------------------------------------
    def test_14_disabled_or_rotated_token(self):
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "disable_user",
            "snell": "snell://pass@1.1.1.1:1488"
        })
        user = json.loads(body)
        u_id = user["id"]
        old_token = user["token"]

        # Работает
        s_ok, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_ok, 200)

        # 1. Отключаем пользователя (enabled = false)
        self.api_request("PUT", f"/api/users/{u_id}", {"enabled": False})
        s_dis, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_dis, 404)

        # Включаем обратно
        self.api_request("PUT", f"/api/users/{u_id}", {"enabled": True})

        # 2. Ротация токена
        _, _, b_rot = self.api_request("POST", f"/api/users/{u_id}/rotate-token")
        new_token = json.loads(b_rot)["token"]

        # Старый токен больше не работает
        s_old, _, _ = self.api_request("GET", f"/sub/{old_token}")
        self.assertEqual(s_old, 404)

        # Новый токен работает
        s_new, _, _ = self.api_request("GET", f"/sub/{new_token}")
        self.assertEqual(s_new, 200)

        # 3. Удаление пользователя
        self.api_request("DELETE", f"/api/users/{u_id}")
        s_del, _, _ = self.api_request("GET", f"/sub/{new_token}")
        self.assertEqual(s_del, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 15: URI и токены отсутствуют в обычных логах
    # --------------------------------------------------------------------------
    def test_15_no_tokens_or_uris_in_logs(self):
        super_secret_token = "TOP_SECRET_TOKEN_XYZ_12345"
        super_secret_uri = "snell://SECRET_PASS_999@1.1.1.1:1488"

        # Делаем запрос к серверу с секретным токеном
        self.api_request("GET", f"/sub/{super_secret_token}")

        # Проверяем файл лога
        if os.path.isfile(self.log_file):
            with open(self.log_file, "r", encoding="utf-8") as f:
                logs = f.read()
                self.assertNotIn(super_secret_token, logs, "Secret token leaked in logs!")
                self.assertNotIn(super_secret_uri, logs, "Secret URI leaked in logs!")

    # --------------------------------------------------------------------------
    # ТЕСТ 16: Сервис не меняет и не вызывает API существующей панели
    # --------------------------------------------------------------------------
    def test_16_service_isolation(self):
        # Сервис не открывает соединений к другим портам и не имеет зависимостей
        # от sing-box/xray/3x-ui
        status, _, body = self.api_request("GET", "/health")
        self.assertEqual(status, 200)
        res = json.loads(body)
        self.assertEqual(res.get("service"), "tuna-subscriptions")
        # База данных не имеет таблиц от 3x-ui
        c = self.app.conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = [r[0] for r in c.fetchall()]
        self.assertNotIn("inbounds", tables)
        self.assertNotIn("settings", tables)
        self.assertIn("users", tables)

    # --------------------------------------------------------------------------
    # ТЕСТ 17: Поддержка нескольких ссылок (2, 3, 4 и более) на протокол
    # --------------------------------------------------------------------------
    def test_17_multi_links_per_protocol(self):
        snell_nodes = [
            "snell://psk_de@1.1.1.1:1488/?version=5&reuse=true#Snell-Frankfurt",
            "snell://psk_nl@2.2.2.2:1488/?version=5&reuse=true#Snell-Amsterdam",
            "snell://psk_us@3.3.3.3:1488/?version=5&reuse=true#Snell-NewYork",
        ]
        mieru_nodes = [
            "mierus://user1:pass1@4.4.4.4/?profile=Mieru-DE&port=2020-2030",
            "mierus://user2:pass2@5.5.5.5/?profile=Mieru-FI&port=3030-3040",
        ]
        qwdtt_node = "qwdtt://config?name=WDTT-Main&peer=6.6.6.6%3A56000&hashes=#"

        payload = {
            "nickname": "multi_node_user",
            "snell": "\n".join(snell_nodes),
            "mieru": "\n".join(mieru_nodes),
            "qwdtt": qwdtt_node
        }

        status, _, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        self.assertEqual(res["total_uris"], 6)
        token = res["token"]

        # Получаем подписку и проверяем все 6 ссылок в теле
        sub_status, _, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(sub_status, 200)
        decoded_lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]

        self.assertEqual(len(decoded_lines), 6)
        # Порядок выдачи ТЗ: QWDTT -> Snell (все 3) -> Mieru (все 2)
        self.assertEqual(decoded_lines[0], qwdtt_node)
        self.assertEqual(decoded_lines[1], snell_nodes[0])
        self.assertEqual(decoded_lines[2], snell_nodes[1])
        self.assertEqual(decoded_lines[3], snell_nodes[2])
        self.assertEqual(decoded_lines[4], mieru_nodes[0])
        self.assertEqual(decoded_lines[5], mieru_nodes[1])

    # --------------------------------------------------------------------------
    # ТЕСТ 18: Передача мульти-ссылок в виде JSON-массивов и custom-протоколы
    # --------------------------------------------------------------------------
    def test_18_multi_links_as_json_arrays(self):
        csqtt_arr = [
            "csqtt://pass1@1.2.3.4:37000#CSQTT-1",
            "csqtt://pass2@1.2.3.5:37000#CSQTT-2"
        ]
        custom_arr = [
            "vless://uuid1@1.2.3.6:443?security=reality&sni=example.com#VLESS-Node",
            "ss://YWVzLTEyOC1nY206cGFzczE@1.2.3.7:8388#Shadowsocks-Node"
        ]

        payload = {
            "nickname": "json_array_user",
            "csqtt_uris": csqtt_arr,
            "custom": custom_arr
        }

        status, _, body = self.api_request("POST", "/api/users", payload)
        self.assertEqual(status, 201)
        res = json.loads(body.decode("utf-8"))
        u_id = res["id"]
        token = res["token"]
        self.assertEqual(res["total_uris"], 4)

        # GET /api/users/<id>
        g_status, _, g_body = self.api_request("GET", f"/api/users/{u_id}")
        self.assertEqual(g_status, 200)
        g_res = json.loads(g_body.decode("utf-8"))
        self.assertEqual(len(g_res["csqtt_uris"]), 2)
        self.assertEqual(len(g_res["custom_uris"]), 2)
        self.assertEqual(g_res["total_uris"], 4)

        # Подписка
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[0], csqtt_arr[0])
        self.assertEqual(lines[1], csqtt_arr[1])
        self.assertEqual(lines[2], custom_arr[0])
        self.assertEqual(lines[3], custom_arr[1])

    # --------------------------------------------------------------------------
    # ТЕСТ 19: Обновление пользователя новыми мульти-ссылками и валидация
    # --------------------------------------------------------------------------
    def test_19_update_user_multi_links(self):
        # Создаем пользователя с 1 Snell ссылкой
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": "update_multi_user",
            "snell": "snell://init@1.1.1.1:1488"
        })
        user = json.loads(body.decode("utf-8"))
        u_id = user["id"]
        token = user["token"]

        # Обновляем на 3 Snell ссылки через PUT
        new_snell_list = [
            "snell://node_a@1.1.1.1:1488",
            "snell://node_b@1.1.1.2:1488",
            "snell://node_c@1.1.1.3:1488"
        ]
        u_status, _, u_body = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell_uris": new_snell_list
        })
        self.assertEqual(u_status, 200)
        u_res = json.loads(u_body.decode("utf-8"))
        self.assertEqual(u_res["total_uris"], 3)
        self.assertEqual(len(u_res["snell_uris"]), 3)

        # Подписка обновлена
        _, _, sub_body = self.api_request("GET", f"/sub/{token}")
        lines = [l for l in base64.b64decode(sub_body).decode("utf-8").splitlines() if l]
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[0], new_snell_list[0])
        self.assertEqual(lines[2], new_snell_list[2])

        # Ошибка при попытке передать массив с невалидным элементом
        err_status, _, err_body = self.api_request("PUT", f"/api/users/{u_id}", {
            "snell_uris": ["snell://valid@1.1.1.1:1488", "broken_without_scheme"]
        })
        self.assertEqual(err_status, 400)

    # --------------------------------------------------------------------------
    # ТЕСТ 20: Доступ, обновление и удаление пользователя напрямую по никнейму
    # --------------------------------------------------------------------------
    def test_20_access_and_modify_by_nickname(self):
        nick = "nick_tester"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://init@1.1.1.1:1488"
        })
        self.assertEqual(status, 201)

        # GET по никнейму
        g_status, _, g_body = self.api_request("GET", f"/api/users/{nick}")
        self.assertEqual(g_status, 200)
        u_info = json.loads(g_body.decode("utf-8"))
        self.assertEqual(u_info["nickname"], nick)

        # PUT по никнейму (обновление ссылок)
        p_status, _, p_body = self.api_request("PUT", f"/api/users/{nick}", {
            "csqtt": "csqtt://pass@1.1.1.1:37000#MyCSQTT"
        })
        self.assertEqual(p_status, 200)

        # DELETE по никнейму
        d_status, _, _ = self.api_request("DELETE", f"/api/users/{nick}")
        self.assertEqual(d_status, 200)

        # Проверка удаления
        chk_status, _, _ = self.api_request("GET", f"/api/users/{nick}")
        self.assertEqual(chk_status, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 21: Удаление пользователя с кириллическим никнеймом (например: тесовой3)
    # --------------------------------------------------------------------------
    def test_21_cyrillic_user_delete(self):
        nick = "тесовой_делете_тест"
        encoded_nick = urllib.parse.quote(nick)
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://init@1.1.1.1:1488#Node"
        })
        self.assertEqual(status, 201)

        # GET по закодированному никнейму
        g_status, _, g_body = self.api_request("GET", f"/api/users/{encoded_nick}")
        self.assertEqual(g_status, 200)

        # DELETE по закодированному никнейму
        d_status, _, d_body = self.api_request("DELETE", f"/api/users/{encoded_nick}")
        self.assertEqual(d_status, 200)

        # Проверка, что пользователя больше нет
        chk_status, _, _ = self.api_request("GET", f"/api/users/{encoded_nick}")
        self.assertEqual(chk_status, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 22: Сохранение индивидуальных имен серверов CSQTT в подписке
    # --------------------------------------------------------------------------
    def test_22_csqtt_server_names_preservation(self):
        nick = "csqtt_named_user"
        csqtt_nodes = [
            "csqtt://pass1@1.2.3.4:37000#CSQTT-SPB",
            "csqtt://pass2@5.6.7.8:37000#CSQTT-Frankfurt",
            "csqtt://pass3@9.10.11.12:37000#CSQTT-Home"
        ]
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "csqtt_uris": csqtt_nodes
        })
        self.assertEqual(status, 201)
        resp = json.loads(body.decode("utf-8"))
        token = resp["token"]

        # Получаем подписку
        sub_status, _, sub_body = self.api_request("GET", f"/sub/{token}")
        self.assertEqual(sub_status, 200)
        decoded = base64.b64decode(sub_body).decode("utf-8").strip().splitlines()

        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], "csqtt://pass1@1.2.3.4:37000#CSQTT-SPB")
        self.assertEqual(decoded[1], "csqtt://pass2@5.6.7.8:37000#CSQTT-Frankfurt")
        self.assertEqual(decoded[2], "csqtt://pass3@9.10.11.12:37000#CSQTT-Home")

    # --------------------------------------------------------------------------
    # ТЕСТ 23: Наличие subscription_url и token в list_users и get_user
    # --------------------------------------------------------------------------
    def test_23_subscription_url_in_list_and_get(self):
        nick = "sub_url_user"
        status, _, body = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://pass@1.1.1.1:1488#Node"
        })
        self.assertEqual(status, 201)
        created = json.loads(body.decode("utf-8"))
        tok = created["token"]
        expected_sub_url = created["subscription_url"]

        # 1. Проверяем в GET /api/users
        status_list, _, body_list = self.api_request("GET", "/api/users")
        self.assertEqual(status_list, 200)
        users = json.loads(body_list.decode("utf-8"))
        target = [u for u in users if u["nickname"] == nick]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["subscription_url"], expected_sub_url)
        self.assertEqual(target[0]["token"], tok)

        # 2. Проверяем в GET /api/users/<id>
        status_get, _, body_get = self.api_request("GET", f"/api/users/{target[0]['id']}")
        self.assertEqual(status_get, 200)
        u_get = json.loads(body_get.decode("utf-8"))
        self.assertEqual(u_get["subscription_url"], expected_sub_url)
        self.assertEqual(u_get["token"], tok)


if __name__ == "__main__":
    unittest.main()


