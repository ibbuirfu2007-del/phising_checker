
from django.test import SimpleTestCase
from scanner.services import analyze_url
from .services import analyze_url, get_risk_level

class AnalyzeURLTests(SimpleTestCase):

    def test_safe_https_url(self):
        result = analyze_url("https://google.com")

        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "Low")

    def test_http_url_with_login(self):
        result = analyze_url("http://example.com/login")

        self.assertEqual(result["risk_score"], 20)
        self.assertEqual(result["risk_level"], "Medium")

    def test_ip_address_url(self):
        result = analyze_url("http://192.168.1.1/login")

        self.assertEqual(result["risk_score"], 45)
        self.assertEqual(result["risk_level"], "Medium")

    def test_multiple_suspicious_keywords(self):
        result = analyze_url(
            "https://secure-account-verify.com"
        )

        self.assertEqual(result["risk_score"], 30)
        self.assertEqual(result["risk_level"], "Medium")

    def test_empty_url(self):
        with self.assertRaises(ValueError):
            analyze_url("")
    
    def test_url_without_scheme(self):
        result = analyze_url("example.com")
        self.assertEqual(result["url"], "http://example.com")

    def test_url_with_spaces(self):
        with self.assertRaises(ValueError):
            analyze_url("hello world")

    def test_url_without_hostname(self):
        with self.assertRaises(ValueError):
            analyze_url("https://")

    def test_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            analyze_url("ftp://example.com")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            analyze_url("https://example.com:99999")
    
    def test_brand_name_in_subdomain(self):
        result = analyze_url(
            "https://paypal.fake-domain.com"
        )

        self.assertIn(
            "Brand name 'paypal' found in subdomain",
            result["reasons"]
        )

    def test_normal_subdomain(self):
        result = analyze_url(
            "https://blog.example.com"
        )

        self.assertNotIn(
            "Brand name 'paypal' found in subdomain",
            result["reasons"]
        )

    
    def test_url_shortener_detection(self):
        result = analyze_url("https://bit.ly/example")

        self.assertIn(
            "URL uses a known shortening service",
            result["reasons"]
        )

    def test_normal_domain_not_shortener(self):
        result = analyze_url("https://example.com")

        self.assertNotIn(
            "URL uses a known shortening service",
            result["reasons"]
        )

    def test_multiple_hyphens_detection(self):
        result = analyze_url(
            "https://secure-account-login-verify.com"
        )

        self.assertIn(
            "Hostname contains multiple hyphens",
            result["reasons"]
        )

    def test_normal_domain_no_multiple_hyphens(self):
        result = analyze_url("https://example.com")

        self.assertNotIn(
            "Hostname contains multiple hyphens",
            result["reasons"]
        )
    
    def test_low_risk_boundary(self):
        self.assertEqual(get_risk_level(14), "Low")

    def test_medium_risk_lower_boundary(self):
        self.assertEqual(get_risk_level(15), "Medium")

    def test_medium_risk_upper_boundary(self):
        self.assertEqual(get_risk_level(49), "Medium")

    def test_high_risk_boundary(self):
        self.assertEqual(get_risk_level(50), "High")

    def test_maximum_risk_score(self):
        self.assertEqual(get_risk_level(100), "High")
    
    def test_analyze_url_risk_level_matches_score(self):
     result = analyze_url("https://example.com")

     self.assertEqual(
        result["risk_level"],
        get_risk_level(result["risk_score"])
    )


