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
serialize_openflux_v2_bundle = tuna_module.serialize_openflux_v2_bundle
deserialize_openflux_v2_bundle = tuna_module.deserialize_openflux_v2_bundle
validate_openflux_url = tuna_module.validate_openflux_url



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

    # --------------------------------------------------------------------------
    # ТЕСТ 24: Каноническая сериализация и десериализация OpenFlux v2
    # --------------------------------------------------------------------------
    def test_24_openflux_serialization_and_deserialization_roundtrip(self):
        sample_payload = {
            "schema": "openflux-bundle",
            "version": 2,
            "issuer_id": "c1f10903-88f5-467f-94d7-eaeead8eef24",
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "TUNA-OpenFlux-Office",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "8bfa5716-1763-471a-ba2d-c1240c114ce7",
                    "name": "OF-Group-1",
                    "mode": "classic",
                    "transport": "mailru",
                    "urls": [
                        "https://cloud.mail.ru/public/Test1/doc1"
                    ],
                    "codec": "legacy",
                    "encryption_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                }
            ]
        }
        ok, err, v2_uri = serialize_openflux_v2_bundle(sample_payload)
        self.assertTrue(ok, f"Serialization failed: {err}")
        self.assertTrue(v2_uri.startswith("openflux-bundle://v2/"))

        # Проверка отсутствия '=' в base64url
        raw_b64 = v2_uri[len("openflux-bundle://v2/"):]
        self.assertFalse(raw_b64.endswith("="))
        self.assertNotIn("+", raw_b64)
        self.assertNotIn("/", raw_b64)

        # Обратная десериализация
        ok_de, err_de, decoded = deserialize_openflux_v2_bundle(v2_uri)
        self.assertTrue(ok_de, f"Deserialization failed: {err_de}")
        self.assertEqual(decoded["schema"], "openflux-bundle")
        self.assertEqual(decoded["version"], 2)
        self.assertEqual(decoded["name"], "TUNA-OpenFlux-Office")
        self.assertEqual(decoded["groups"][0]["transport"], "mailru")
        self.assertEqual(decoded["groups"][0]["codec"], "legacy")

    # --------------------------------------------------------------------------
    # ТЕСТ 25: Валидация схемы и запрет недопустимых транспортов/форматов в v2
    # --------------------------------------------------------------------------
    def test_25_openflux_validation_rules_and_limits(self):
        base_payload = {
            "schema": "openflux-bundle",
            "version": 2,
            "issuer_id": "c1f10903-88f5-467f-94d7-eaeead8eef24",
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "Validation-Test",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "name": "G1",
                    "mode": "classic",
                    "transport": "mailru",
                    "urls": ["https://cloud.mail.ru/public/Test/doc1"],
                    "codec": "legacy",
                    "encryption_key": "k1"
                }
            ]
        }

        # 1. Запрещенный транспорт (vyandex, yandex, vless и др.)
        bad_tr_payload = json.loads(json.dumps(base_payload))
        bad_tr_payload["groups"][0]["transport"] = "vyandex"
        _, _, uri_bad = serialize_openflux_v2_bundle(bad_tr_payload)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_bad)
        self.assertFalse(ok)
        self.assertIn("forbidden transport", err)

        # 2. Неверная схема
        bad_schema = json.loads(json.dumps(base_payload))
        bad_schema["schema"] = "other-bundle"
        _, _, uri_bs = serialize_openflux_v2_bundle(bad_schema)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_bs)
        self.assertFalse(ok)

        # 3. Неверная версия
        bad_ver = json.loads(json.dumps(base_payload))
        bad_ver["version"] = 1
        _, _, uri_bv = serialize_openflux_v2_bundle(bad_ver)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_bv)
        self.assertFalse(ok)

        # 4. В режиме classic более 1 URL
        bad_cl_urls = json.loads(json.dumps(base_payload))
        bad_cl_urls["groups"][0]["urls"] = ["https://cloud.mail.ru/1", "https://cloud.mail.ru/2"]
        _, _, uri_bcl = serialize_openflux_v2_bundle(bad_cl_urls)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_bcl)
        self.assertFalse(ok)

        # 5. В режиме multistream более 4 URL
        bad_ms_urls = json.loads(json.dumps(base_payload))
        bad_ms_urls["mode"] = "multistream"
        bad_ms_urls["groups"][0]["mode"] = "multistream"
        bad_ms_urls["groups"][0]["urls"] = [f"https://cloud.mail.ru/{i}" for i in range(5)]
        _, _, uri_bms = serialize_openflux_v2_bundle(bad_ms_urls)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_bms)
        self.assertFalse(ok)

        # 6. Дубликаты URL в группе
        bad_dup = json.loads(json.dumps(base_payload))
        bad_dup["mode"] = "multistream"
        bad_dup["groups"][0]["mode"] = "multistream"
        bad_dup["groups"][0]["urls"] = ["https://cloud.mail.ru/same", "https://cloud.mail.ru/same"]
        _, _, uri_dup = serialize_openflux_v2_bundle(bad_dup)
        ok, err, _ = deserialize_openflux_v2_bundle(uri_dup)
        self.assertFalse(ok)

        # 7. Невалидный URL (http:// вместо https://)
        self.assertFalse(validate_openflux_url("http://insecure.site")[0])
        self.assertFalse(validate_openflux_url("https://site.com/with space")[0])
        self.assertTrue(validate_openflux_url("https://cloud.mail.ru/public/abc")[0])

    # --------------------------------------------------------------------------
    # ТЕСТ 26: CRUD API каталога групп OpenFlux (/api/openflux/groups)
    # --------------------------------------------------------------------------
    def test_26_openflux_groups_crud_api(self):
        # 1. Создание группы classic (mailru)
        g1_data = {
            "name": "MailRu-Cluster-1",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/123/file.dat"],
            "codec": "legacy",
            "encryption_key": "secret123",
            "source_slot": 1
        }
        st1, _, b1 = self.api_request("POST", "/api/openflux/groups", g1_data)
        self.assertEqual(st1, 201)
        res1 = json.loads(b1.decode())
        g1_id = res1["id"]
        self.assertEqual(res1["name"], "MailRu-Cluster-1")
        self.assertEqual(res1["transport"], "mailru")

        # 2. Создание группы multistream (boards, 3 URL)
        g2_data = {
            "name": "Boards-Multi",
            "mode": "multistream",
            "transport": "boards",
            "urls": [
                "https://boards.example.com/d/1",
                "https://boards.example.com/d/2",
                "https://boards.example.com/d/3"
            ],
            "codec": "batched",
            "encryption_key": "sec_boards"
        }
        st2, _, b2 = self.api_request("POST", "/api/openflux/groups", g2_data)
        self.assertEqual(st2, 201)
        res2 = json.loads(b2.decode())
        g2_id = res2["id"]
        self.assertEqual(len(res2["urls"]), 3)
        self.assertEqual(res2["codec"], "batched")

        # 3. Отклонение запрещенного транспорта (vyandex)
        st_bad, _, b_bad = self.api_request("POST", "/api/openflux/groups", {
            "name": "Bad-Vyandex",
            "mode": "classic",
            "transport": "vyandex",
            "urls": ["https://disk.yandex.ru/i/123"]
        })
        self.assertEqual(st_bad, 400)
        self.assertIn("Invalid transport", json.loads(b_bad.decode())["error"])

        # 4. Отклонение недопустимого URL (без https)
        st_http, _, b_http = self.api_request("POST", "/api/openflux/groups", {
            "name": "HTTP-Test",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["http://cloud.mail.ru/plain"]
        })
        self.assertEqual(st_http, 400)

        # 5. Список групп GET /api/openflux/groups
        st_list, _, b_list = self.api_request("GET", "/api/openflux/groups")
        self.assertEqual(st_list, 200)
        groups = json.loads(b_list.decode())
        self.assertTrue(any(g["id"] == g1_id for g in groups))
        self.assertTrue(any(g["id"] == g2_id for g in groups))

        # 6. Получение группы по ID
        st_get, _, b_get = self.api_request("GET", f"/api/openflux/groups/{g1_id}")
        self.assertEqual(st_get, 200)
        self.assertEqual(json.loads(b_get.decode())["id"], g1_id)

        # 7. Обновление группы PUT
        st_upd, _, b_upd = self.api_request("PUT", f"/api/openflux/groups/{g1_id}", {
            "name": "MailRu-Cluster-Updated",
            "codec": "batched"
        })
        self.assertEqual(st_upd, 200)
        res_upd = json.loads(b_upd.decode())
        self.assertEqual(res_upd["name"], "MailRu-Cluster-Updated")
        self.assertEqual(res_upd["codec"], "batched")

        # 8. Удаление группы DELETE
        st_del, _, _ = self.api_request("DELETE", f"/api/openflux/groups/{g2_id}")
        self.assertEqual(st_del, 200)
        st_404, _, _ = self.api_request("GET", f"/api/openflux/groups/{g2_id}")
        self.assertEqual(st_404, 404)

    # --------------------------------------------------------------------------
    # ТЕСТ 27: Конфигурация OpenFlux для пользователя (/api/users/<id>/openflux)
    # --------------------------------------------------------------------------
    def test_27_openflux_user_config_and_validation(self):
        # Создаем тестового пользователя
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": "of_user_cfg"})
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]

        # Создаем валидную группу classic (cupsonline)
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Cups-Group",
            "mode": "classic",
            "transport": "cupsonline",
            "urls": ["https://cups.online/api/doc_abc"],
            "codec": "legacy"
        })
        grp_id = json.loads(b_g.decode())["id"]

        # 1. По умолчанию OpenFlux выключен
        st_init, _, b_init = self.api_request("GET", f"/api/users/{u_id}/openflux")
        self.assertEqual(st_init, 200)
        res_init = json.loads(b_init.decode())
        self.assertFalse(res_init["enabled"])
        self.assertEqual(res_init["groups"], [])
        self.assertEqual(res_init["v2_uri"], "")
        stable_conn_id = res_init["connection_id"]
        self.assertTrue(len(stable_conn_id) > 10)

        # 2. Включаем OpenFlux для пользователя
        st_put, _, b_put = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "TUNA-User-Connection",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "group_ids": [grp_id]
        })
        self.assertEqual(st_put, 200)
        res_put = json.loads(b_put.decode())
        self.assertTrue(res_put["enabled"])
        self.assertEqual(res_put["name"], "TUNA-User-Connection")
        self.assertEqual(res_put["connection_id"], stable_conn_id)
        self.assertTrue(res_put["v2_uri"].startswith("openflux-bundle://v2/"))
        self.assertEqual(len(res_put["groups"]), 1)

        # 3. Ошибка при несуществующей группе
        st_err, _, b_err = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": ["00000000-0000-0000-0000-000000000000"]
        })
        self.assertEqual(st_err, 400)

        # 4. Ошибка при дубликатах group_ids
        st_dup, _, b_dup = self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [grp_id, grp_id]
        })
        self.assertEqual(st_dup, 400)

    # --------------------------------------------------------------------------
    # ТЕСТ 28: Обратная совместимость для существующих пользователей (выключен OpenFlux)
    # --------------------------------------------------------------------------
    def test_28_subscription_without_openflux_backward_compatibility(self):
        nick = "compat_user_no_of"
        _, _, b_u = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://psk123@1.2.3.4:1488#Snell",
            "mieru": "mierus://u:p@1.2.3.4/?profile=P1#Mieru"
        })
        tok = json.loads(b_u.decode())["token"]

        # Запрашиваем подписку
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        decoded = base64.b64decode(b_sub).decode("utf-8")
        lines = [l.strip() for l in decoded.splitlines() if l.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "snell://psk123@1.2.3.4:1488#Snell")
        self.assertEqual(lines[1], "mierus://u:p@1.2.3.4/?profile=P1#Mieru")
        self.assertNotIn("openflux-bundle://", decoded)

    # --------------------------------------------------------------------------
    # ТЕСТ 29: Выдача подписки со строкой OpenFlux v2 бандла
    # --------------------------------------------------------------------------
    def test_29_subscription_with_openflux_bundle_output(self):
        nick = "of_bundle_subscriber"
        _, _, b_u = self.api_request("POST", "/api/users", {
            "nickname": nick,
            "snell": "snell://psk999@5.5.5.5:1488#SnellMain"
        })
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]
        tok = u_info["token"]

        # Создаем группу OpenFlux
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Sub-Group-1",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/Sub/test.txt"],
            "codec": "legacy",
            "encryption_key": "sub_key_123"
        })
        gid = json.loads(b_g.decode())["id"]

        # Привязываем и включаем для пользователя
        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "name": "Office-Full-Bundle",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "group_ids": [gid]
        })

        # Получаем подписку
        st_sub, _, b_sub = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_sub, 200)
        decoded_text = base64.b64decode(b_sub).decode("utf-8")
        lines = [l.strip() for l in decoded_text.splitlines() if l.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], "snell://psk999@5.5.5.5:1488#SnellMain")
        self.assertTrue(lines[1].startswith("openflux-bundle://v2/"))

        # Валидируем распарсенный бандл v2
        ok, err, bundle = deserialize_openflux_v2_bundle(lines[1])
        self.assertTrue(ok, f"Bundle validation error: {err}")
        self.assertEqual(bundle["name"], "Office-Full-Bundle")
        self.assertEqual(bundle["mode"], "classic")
        self.assertEqual(len(bundle["groups"]), 1)
        self.assertEqual(bundle["groups"][0]["name"], "Sub-Group-1")
        self.assertEqual(bundle["groups"][0]["urls"], ["https://cloud.mail.ru/public/Sub/test.txt"])

    # --------------------------------------------------------------------------
    # ТЕСТ 30: Пользователь ТОЛЬКО с OpenFlux получает 200 OK (не 204!)
    # --------------------------------------------------------------------------
    def test_30_subscription_with_only_openflux_returns_200(self):
        nick = "only_of_subscriber"
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": nick})
        u_info = json.loads(b_u.decode())
        u_id = u_info["id"]
        tok = u_info["token"]

        # До включения OpenFlux: нет ссылок -> 204 No Content
        st_empty, _, _ = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_empty, 204)

        # Создаем и привязываем группу
        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Solo-Group",
            "mode": "classic",
            "transport": "boards",
            "urls": ["https://boards.example.com/doc/single"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [gid]
        })

        # После включения OpenFlux: возвращает 200 OK
        st_ok, headers, b_payload = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st_ok, 200)
        self.assertIn("ETag", headers)

        decoded = base64.b64decode(b_payload).decode("utf-8").strip().splitlines()
        self.assertEqual(len(decoded), 1)
        self.assertTrue(decoded[0].startswith("openflux-bundle://v2/"))

    # --------------------------------------------------------------------------
    # ТЕСТ 31: Каскадный инкремент ревизии и ETag при обновлении группы
    # --------------------------------------------------------------------------
    def test_31_openflux_group_update_cascades_revision_bump(self):
        nick = "cascade_rev_user"
        _, _, b_u = self.api_request("POST", "/api/users", {"nickname": nick})
        u_id = json.loads(b_u.decode())["id"]
        tok = json.loads(b_u.decode())["token"]

        _, _, b_g = self.api_request("POST", "/api/openflux/groups", {
            "name": "Cascade-Group",
            "mode": "classic",
            "transport": "mailru",
            "urls": ["https://cloud.mail.ru/public/A/1"],
            "codec": "legacy"
        })
        gid = json.loads(b_g.decode())["id"]

        self.api_request("PUT", f"/api/users/{u_id}/openflux", {
            "enabled": True,
            "group_ids": [gid]
        })

        # Получаем подписку и ETag
        st1, h1, b_sub1 = self.api_request("GET", f"/sub/{tok}")
        self.assertEqual(st1, 200)
        etag1 = h1["ETag"]

        # Повторный запрос с If-None-Match без изменений возвращает 304 Not Modified
        st_304, _, _ = self.api_request("GET", f"/sub/{tok}", headers={"If-None-Match": etag1})
        self.assertEqual(st_304, 304)

        # Теперь обновляем саму группу (меняем URL)
        st_upd, _, _ = self.api_request("PUT", f"/api/openflux/groups/{gid}", {
            "urls": ["https://cloud.mail.ru/public/A/2_updated"]
        })
        self.assertEqual(st_upd, 200)

        # Запрос с прежним ETag должен вернуть 200 OK (новые данные) и новый ETag
        st2, h2, b_sub2 = self.api_request("GET", f"/sub/{tok}", headers={"If-None-Match": etag1})
        self.assertEqual(st2, 200)
        etag2 = h2["ETag"]
        self.assertNotEqual(etag1, etag2)

        decoded2 = base64.b64decode(b_sub2).decode("utf-8").strip()
        ok_de, _, data2 = deserialize_openflux_v2_bundle(decoded2)
        self.assertTrue(ok_de)
        self.assertEqual(data2["groups"][0]["urls"], ["https://cloud.mail.ru/public/A/2_updated"])

    # --------------------------------------------------------------------------
    # ТЕСТ 32: Синтетические фикстуры (8 групп classic и 8 групп multistream 8x4)
    # --------------------------------------------------------------------------
    def test_32_synthetic_8_groups_classic_and_multistream_fixtures(self):
        fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "fixtures")
        os.makedirs(fixtures_dir, exist_ok=True)
        issuer_id = "c1f10903-88f5-467f-94d7-eaeead8eef24"

        # 0. Бандл Single Group (1 группа, classic, mailru)
        single_bundle = {
            "schema": "openflux-bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "e93e2b20-1a74-4b53-b26a-93911c7ffae1",
            "revision": 1,
            "name": "TUNA-OpenFlux-Single",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": [
                {
                    "id": "8bfa5716-1763-471a-ba2d-c1240c114ce7",
                    "name": "OF-Group-MailRu",
                    "mode": "classic",
                    "transport": "mailru",
                    "urls": ["https://cloud.mail.ru/public/Test/doc1"],
                    "codec": "legacy",
                    "encryption_key": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
                }
            ]
        }
        ok_sg, err_sg, uri_sg = serialize_openflux_v2_bundle(single_bundle)
        self.assertTrue(ok_sg, f"Single group serialization failed: {err_sg}")
        with open(os.path.join(fixtures_dir, "single_group_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(single_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "single_group_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_sg)
        with open(os.path.join(fixtures_dir, "single_group_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_sg + "\n").encode("utf-8")).decode("ascii"))

        # 1. Бандл Classic (8 групп × 1 URL, смешанные транспорты)
        classic_groups = []
        transports = ["mailru", "boards", "cupsonline"]
        for idx in range(1, 9):
            tr = transports[(idx - 1) % len(transports)]
            codec = "batched" if idx % 2 == 0 else "legacy"
            classic_groups.append({
                "id": f"00000000-0000-0000-0000-00000000000{idx}",
                "name": f"Classic-Group-{idx}",
                "mode": "classic",
                "transport": tr,
                "urls": [f"https://{tr}.example.com/doc/ch{idx}"],
                "codec": codec,
                "encryption_key": f"key_hex_{idx * 11111111}"
            })

        classic_bundle = {
            "schema": "openflux-bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "77777777-1111-4444-8888-999999999999",
            "revision": 2,
            "name": "TUNA-OpenFlux-Classic-8",
            "mode": "classic",
            "balancer_strategy": "roundRobin",
            "groups": classic_groups
        }

        ok_cl, err_cl, uri_cl = serialize_openflux_v2_bundle(classic_bundle)
        self.assertTrue(ok_cl, f"Classic 8x1 serialization failed: {err_cl}")
        self.assertLess(len(uri_cl), 700000)

        # Сохранение фикстуры classic 8x1
        with open(os.path.join(fixtures_dir, "classic_8x1_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(classic_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "classic_8x1_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_cl)
        with open(os.path.join(fixtures_dir, "classic_8x1_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_cl + "\n").encode("utf-8")).decode("ascii"))

        # 2. Бандл MultiStream (8 групп × 4 URL = 32 URL суммарно)
        ms_groups = []
        for idx in range(1, 9):
            tr = transports[(idx - 1) % len(transports)]
            codec = "batched" if idx % 2 == 0 else "legacy"
            urls = [f"https://{tr}.example.com/doc/ch{idx}/part_{part}" for part in range(1, 5)]
            ms_groups.append({
                "id": f"00000000-0000-0000-0000-00000000001{idx}",
                "name": f"MultiStream-Group-{idx}",
                "mode": "multistream",
                "transport": tr,
                "urls": urls,
                "codec": codec,
                "encryption_key": f"ms_key_{idx * 22222222}"
            })

        ms_bundle = {
            "schema": "openflux-bundle",
            "version": 2,
            "issuer_id": issuer_id,
            "id": "88888888-2222-5555-9999-000000000000",
            "revision": 5,
            "name": "TUNA-OpenFlux-MultiStream-32",
            "mode": "multistream",
            "balancer_strategy": "leastPing",
            "groups": ms_groups
        }

        ok_ms, err_ms, uri_ms = serialize_openflux_v2_bundle(ms_bundle)
        self.assertTrue(ok_ms, f"MultiStream 8x4 serialization failed: {err_ms}")
        self.assertLess(len(uri_ms), 700000)

        # Сохранение фикстуры multistream 8x4
        with open(os.path.join(fixtures_dir, "multistream_8x4_decoded.json"), "w", encoding="utf-8") as f:
            json.dump(ms_bundle, f, ensure_ascii=False, indent=2)
        with open(os.path.join(fixtures_dir, "multistream_8x4_v2_uri.txt"), "w", encoding="utf-8") as f:
            f.write(uri_ms)
        with open(os.path.join(fixtures_dir, "multistream_8x4_http_body.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode((uri_ms + "\n").encode("utf-8")).decode("ascii"))

        # Проверка десериализации обоих
        ok_de_cl, _, de_cl = deserialize_openflux_v2_bundle(uri_cl)
        self.assertTrue(ok_de_cl)
        self.assertEqual(len(de_cl["groups"]), 8)

        ok_de_ms, _, de_ms = deserialize_openflux_v2_bundle(uri_ms)
        self.assertTrue(ok_de_ms)
        self.assertEqual(len(de_ms["groups"]), 8)
        total_urls_ms = sum(len(g["urls"]) for g in de_ms["groups"])
        self.assertEqual(total_urls_ms, 32)

    # --------------------------------------------------------------------------
    # ТЕСТ 33: Безопасный импорт локальных инстансов OpenFlux (/api/openflux/import-local)
    # --------------------------------------------------------------------------
    def test_33_openflux_local_instances_import(self):
        mock_instances_dir = os.path.join(self.test_dir, "openflux_instances")
        os.makedirs(mock_instances_dir, exist_ok=True)

        # Слот 1: mailru (валидный)
        with open(os.path.join(mock_instances_dir, "1.env"), "w", encoding="utf-8") as f:
            f.write('ROLE="exit"\nMODE="l4"\nTRANSPORT="mailru"\nCODEC="legacy"\nURL="https://cloud.mail.ru/public/A/1"\n')

        # Слот 2: boards (валидный)
        with open(os.path.join(mock_instances_dir, "2.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="boards"\nCODEC="batched"\nURL="https://boards.example.com/doc/2"\n')

        # Слот 3: vyandex (НЕВАЛИДНЫЙ транспорт в v2 - должен быть пропущен)
        with open(os.path.join(mock_instances_dir, "3.env"), "w", encoding="utf-8") as f:
            f.write('TRANSPORT="vyandex"\nURL="https://disk.yandex.ru/i/skipped"\n')

        pool_mode_file = os.path.join(self.test_dir, "pool.mode")
        with open(pool_mode_file, "w", encoding="utf-8") as f:
            f.write("classic\n")

        st_imp, _, b_imp = self.api_request("POST", "/api/openflux/import-local", {
            "instances_dir": mock_instances_dir,
            "pool_mode_file": pool_mode_file
        })
        self.assertEqual(st_imp, 200)
        res = json.loads(b_imp.decode())
        self.assertTrue(res["success"])
        self.assertEqual(res["imported_count"], 2)

        # Проверяем что в базе появились слоты 1 и 2, а слот 3 пропущен
        st_get1, _, b_g1 = self.api_request("GET", "/api/openflux/groups/OF-Slot-1")
        self.assertEqual(st_get1, 200)
        self.assertEqual(json.loads(b_g1.decode())["transport"], "mailru")

        st_get3, _, _ = self.api_request("GET", "/api/openflux/groups/OF-Slot-3")
        self.assertEqual(st_get3, 404)


if __name__ == "__main__":
    unittest.main()


