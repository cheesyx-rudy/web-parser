import base64
import unittest

from main import extract_configs, make_request_url, Source


class ExtractConfigsTests(unittest.TestCase):
    def test_extracts_supported_uri_schemes(self):
        body = "vless://one#A\nvmess://two#B\ntrojan://three#C"
        self.assertEqual(extract_configs(body), ["vless://one#A", "vmess://two#B", "trojan://three#C"])

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


if __name__ == "__main__":
    unittest.main()
