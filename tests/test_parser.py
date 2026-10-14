import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from main import extract_configs, make_request_url, Source


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
