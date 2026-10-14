import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from main import extract_configs, make_request_url, Source, proxy_json_payload, convert_proxy_json
from local_converter import convert_proxy_json_to_urls, is_supported_proxy_json


class ExtractConfigsTests(unittest.TestCase):
    def test_extracts_supported_uri_schemes(self):
        body = "vless://one#A\nvmess://two#B\ntrojan://three#C"
        self.assertEqual(extract_configs(body), ["vless://one#A", "vmess://two#B", "trojan://three#C"])

    def test_ignores_ordinary_website_links(self):
        body = "vless://proxy-one\nhttps://t.me/quorvpn\nhttps://t.me/QuorVPN\nvless://proxy-two"
        self.assertEqual(extract_configs(body), ["vless://proxy-one", "vless://proxy-two"])

    def test_deduplicates(self):
        body = "vless://example\nvless://example"
        self.assertEqual(extract_configs(body), ["vless://example"])

    def test_decodes_base64_subscription(self):
        original = "vless://example-a\nvmess://example-b"
        body = base64.b64encode(original.encode()).decode()
        self.assertEqual(extract_configs(body), ["vless://example-a", "vmess://example-b"])

    def test_p_kfwl_url_is_composed(self):
        source = Source(name="test", url="https://sub.example/abc", mode="p_kfwl", user_agent="Happ", os_name="android", hwid="abc123")
        url = make_request_url(source)
        self.assertTrue(url.startswith("https://p.kfwl.lol/ua=Happ/os=android/h=abc123/url/https://sub.example/abc"))

    def test_detects_xray_json_full_config(self):
        body = json.dumps({
            "outbounds": [{
                "protocol": "vless",
                "tag": "test-node",
                "settings": {"vnext": [{"address": "example.org", "port": 443, "users": [{"id": "00000000-0000-0000-0000-000000000000"}]}]},
                "streamSettings": {"network": "tcp", "security": "tls"},
            }]
        })
        self.assertIsNotNone(proxy_json_payload(body))

    def test_detects_sing_box_json_full_config(self):
        body = json.dumps({
            "outbounds": [{
                "type": "vless", "tag": "test-node", "server": "example.org", "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000000",
            }, {"type": "direct", "tag": "direct"}]
        })
        self.assertIsNotNone(proxy_json_payload(body))

    def test_ignores_unrelated_json(self):
        self.assertIsNone(proxy_json_payload('{"title":"website metadata","items":[{"id":1}]}'))

    def test_converts_singbox_vless_json_locally(self):
        body = json.dumps({"outbounds": [{
            "type": "vless", "tag": "node test", "server": "example.org", "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000",
            "tls": {"enabled": True, "server_name": "cdn.example.org", "utls": {"enabled": True, "fingerprint": "chrome"}},
            "transport": {"type": "ws", "path": "/edge", "headers": {"Host": "cdn.example.org"}},
        }]})
        source = Source(name="test", url="https://sub.example/json")
        with patch("main.requests.post", side_effect=AssertionError("should not call a third-party converter")):
            converted = convert_proxy_json(body, source, {"convert_json": True})
        self.assertIsNotNone(converted)
        self.assertIn("vless://00000000-0000-0000-0000-000000000000@example.org:443?", converted)
        self.assertIn("security=tls", converted)
        self.assertIn("sni=cdn.example.org", converted)
        self.assertIn("type=ws", converted)
        self.assertIn("path=%2Fedge", converted)
        self.assertIn("#node%20test", converted)

    def test_fetch_source_uses_local_json_converter_without_posting_to_external_service(self):
        body = json.dumps({"outbounds": [{
            "type": "vless", "tag": "local", "server": "example.org", "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000000"
        }]})

        class FakeResponse:
            status_code = 200
            encoding = "utf-8"
            headers = {"Content-Type": "application/json"}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def raise_for_status(self):
                return None

            def iter_content(self, chunk_size=65536):
                yield body.encode()

        source = Source(name="json-test", url="https://source.example/json", retries=0)
        with patch("main.requests.get", return_value=FakeResponse()), patch(
            "main.requests.post", side_effect=AssertionError("external JSON converter must not be called")
        ):
            configs = main.fetch_source(source, {"convert_json": True, "decode_base64": True, "max_body_bytes": 100000})
        self.assertEqual(len(configs), 1)
        self.assertTrue(configs[0].startswith("vless://"))

    def test_converts_xray_vless_reality_json_locally(self):
        body = json.dumps({"outbounds": [{
            "protocol": "vless", "tag": "reality-node",
            "settings": {"vnext": [{"address": "example.org", "port": 443, "users": [{
                "id": "00000000-0000-0000-0000-000000000000", "encryption": "none", "flow": "xtls-rprx-vision"
            }]}]},
            "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {
                "serverName": "www.example.org", "fingerprint": "chrome", "publicKey": "public-key", "shortId": "a1b2", "spiderX": "/"
            }}
        }]})
        converted = convert_proxy_json_to_urls(body)
        self.assertEqual(len(converted), 1)
        self.assertTrue(converted[0].startswith("vless://"))
        self.assertIn("security=reality", converted[0])
        self.assertIn("pbk=public-key", converted[0])
        self.assertIn("sid=a1b2", converted[0])
        self.assertIn("flow=xtls-rprx-vision", converted[0])

    def test_converts_xray_vmess_to_base64_json(self):
        body = json.dumps({"outbounds": [{
            "protocol": "vmess", "tag": "vmess node",
            "settings": {"vnext": [{"address": "example.org", "port": 8443, "users": [{"id": "abc", "alterId": 0, "security": "auto"}]}]},
            "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "example.org"}, "wsSettings": {"path": "/ws", "headers": {"Host": "cdn.example.org"}}}
        }]})
        converted = convert_proxy_json_to_urls(body)
        self.assertEqual(len(converted), 1)
        self.assertTrue(converted[0].startswith("vmess://"))
        encoded = converted[0][len("vmess://"):]
        vmess = json.loads(base64.b64decode(encoded).decode())
        self.assertEqual(vmess["add"], "example.org")
        self.assertEqual(vmess["net"], "ws")
        self.assertEqual(vmess["path"], "/ws")
        self.assertEqual(vmess["tls"], "tls")

    def test_converts_shadowsocks_and_skips_direct_outbound(self):
        body = json.dumps({"outbounds": [
            {"type": "shadowsocks", "tag": "ss-node", "server": "ss.example", "server_port": 8388, "method": "aes-128-gcm", "password": "secret"},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"}
        ]})
        converted = convert_proxy_json_to_urls(body)
        self.assertEqual(len(converted), 1)
        self.assertTrue(converted[0].startswith("ss://"))
        self.assertIn("@ss.example:8388#ss-node", converted[0])

    def test_http_proxy_generated_from_json_is_kept_even_though_html_links_are_filtered(self):
        body = json.dumps({"outbounds": [{
            "type": "http", "tag": "http node", "server": "proxy.example", "server_port": 8080,
            "username": "alice", "password": "p@ss word"
        }]})
        converted = convert_proxy_json_to_urls(body)
        self.assertEqual(len(converted), 1)
        self.assertTrue(converted[0].startswith("http://alice:p%40ss%20word@proxy.example:8080#http%20node"))

    def test_converts_singbox_hysteria2(self):
        body = json.dumps({"outbounds": [{
            "type": "hysteria2", "tag": "hy2", "server": "hy.example", "server_port": 443,
            "password": "secret", "tls": {"enabled": True, "server_name": "hy.example", "alpn": ["h3"]},
            "obfs": {"type": "salamander", "password": "obfs-secret"}
        }]})
        converted = convert_proxy_json_to_urls(body)
        self.assertEqual(len(converted), 1)
        self.assertTrue(converted[0].startswith("hysteria2://secret@hy.example:443?"))
        self.assertIn("obfs=salamander", converted[0])
        self.assertIn("obfs-password=obfs-secret", converted[0])

    def test_supports_json_wrapped_as_string_and_ignores_unrelated_json(self):
        inner = json.dumps({"type": "trojan", "tag": "tr", "server": "example.org", "server_port": 443, "password": "secret", "tls": {"enabled": True, "server_name": "example.org"}})
        self.assertTrue(is_supported_proxy_json(json.dumps({"data": inner})))
        self.assertEqual(len(convert_proxy_json_to_urls(json.dumps({"data": inner}))), 1)
        self.assertFalse(is_supported_proxy_json('{"title":"website metadata","items":[{"id":1}]}'))

    def test_sync_json_adds_new_url_and_removes_deleted_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "sources.json"
            config_path.write_text(json.dumps({
                "defaults": {"timeout_seconds": 30},
                "sources": [
                    {"name": "keep-me", "url": "https://keep.example/sub", "mode": "direct", "user_agent": "CustomUA", "headers": {"X-Test": "1"}},
                    {"name": "remove-me", "url": "https://remove.example/sub", "mode": "direct"}
                ]
            }), encoding="utf-8")

            with patch.object(main, "CONFIG_PATH", config_path):
                synced = main.sync_json_sources(
                    ["https://keep.example/sub", "https://new.example/sub"],
                    {"timeout_seconds": 30, "retries": 2, "user_agent": "Happ/3.0.0"},
                )

            self.assertEqual([item["url"] for item in synced], ["https://keep.example/sub", "https://new.example/sub"])
            self.assertEqual(synced[0]["user_agent"], "CustomUA")
            self.assertEqual(synced[1]["user_agent"], "Happ/3.0.0")
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(len(saved["sources"]), 2)
            self.assertNotIn("https://remove.example/sub", [item["url"] for item in saved["sources"]])


if __name__ == "__main__":
    unittest.main()
