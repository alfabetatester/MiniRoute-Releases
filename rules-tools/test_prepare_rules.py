import io
import unittest
from unittest.mock import patch
import prepare_rules


class Response(io.BytesIO):
    status = 200


class PrepareRulesTests(unittest.TestCase):
    def test_rejects_html_error_and_oversized_source(self):
        for data in (b"<html>unavailable</html>", b"", b"x" * (prepare_rules.LIMIT + 1)):
            with patch("urllib.request.urlopen", return_value=Response(data)):
                with self.assertRaises(ValueError):
                    prepare_rules.download("https://example.com/filter")

    def test_bundles_five_filters_and_smart_rewrites(self):
        def download(url):
            if "smart-no-crutch" in url:
                return "||chatgpt.com^$dnsrewrite=203.0.113.10\\n"
            return "||ads.example^\\n"
        with patch.object(prepare_rules, "download", side_effect=download):
            bundle = prepare_rules.build()
        self.assertEqual(set(bundle["sources"]), {"oisd", "hagezi", "adguard_dns", "1hosts", "adguard_popup"})
        self.assertIn("chatgpt.com", bundle["rewrites"])
        self.assertEqual(bundle["smartRewrites"], "||chatgpt.com^$dnsrewrite=203.0.113.10\\n")
        self.assertEqual(bundle["rewrites"], bundle["smartRewrites"] + "\n")
        self.assertIn("smart-no-crutch", bundle["provenance"]["smartNoCrutch"])


if __name__ == "__main__":
    unittest.main()
