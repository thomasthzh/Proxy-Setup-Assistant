import unittest
from unittest.mock import patch
import urllib.request

from vps_proxy_setup.cli import SetupError
from vps_proxy_setup.desktop.guidance import REFERRAL_LINKS, SameOriginRedirect, check_referral, monthly_traffic


class GuidanceTests(unittest.TestCase):
    def test_live_budget(self):
        self.assertEqual(monthly_traffic(3, 20, reserve=1), 810)
        self.assertAlmostEqual(monthly_traffic(3, 20), 972)

    def test_invalid_values(self):
        for args in ((float("nan"), 1), (2, 25), (float("inf"), 1), (0, 1), (-1, 1)):
            with self.assertRaises(SetupError):
                monthly_traffic(*args)

    def test_no_certificate_bypass_or_exception_disclosure(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=OSError("TEST_ONLY_PRIVATE_URL")):
            result = check_referral(REFERRAL_LINKS[0])
        self.assertFalse(result.reachable)
        self.assertNotIn("TEST_ONLY", result.message)

    def test_only_user_supplied_links(self):
        with self.assertRaises(SetupError):
            check_referral("https://example.org/")

    def test_cross_origin_and_downgrade_blocked(self):
        handler = SameOriginRedirect()
        request = urllib.request.Request("https://example.org/")
        for new in ("http://example.org/", "https://other.example.org/", "https://example.org:8443/"):
            with self.assertRaises(SetupError):
                handler.redirect_request(request, None, 302, "", {}, new)


if __name__ == "__main__":
    unittest.main()
