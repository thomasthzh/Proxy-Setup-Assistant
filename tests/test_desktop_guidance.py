import unittest
from unittest.mock import patch
import urllib.request

from vps_proxy_setup.cli import SetupError
from vps_proxy_setup.desktop.guidance import (
    REFERRAL_LINKS, SameOriginRedirect, check_referral, monthly_traffic,
    observed_monthly_traffic,
)


class GuidanceTests(unittest.TestCase):
    def test_observed_months_average_group_and_people_without_padding(self):
        result = observed_monthly_traffic(1200, 12, 15, unit="months")
        self.assertEqual(result.group_gb, 100)
        self.assertAlmostEqual(result.per_person_gb, 100 / 15)

    def test_observed_week_uses_a_thirty_day_month(self):
        result = observed_monthly_traffic(7, 7, 2)
        self.assertEqual(result.group_gb, 30)
        self.assertEqual(result.per_person_gb, 15)

    def test_observed_zero_usage_is_valid(self):
        result = observed_monthly_traffic(0, 7)
        self.assertEqual(result.group_gb, 0)
        self.assertEqual(result.per_person_gb, 0)

    def test_observed_text_fields_and_upper_bound(self):
        result = observed_monthly_traffic("12.5", "1", "10000", unit="months")
        self.assertEqual(result.group_gb, 12.5)
        self.assertEqual(result.per_person_gb, .00125)

    def test_observed_rejects_invalid_values(self):
        values = (
            (-1, 7, 1), (float("nan"), 7, 1), (float("inf"), 7, 1),
            (1_000_000_001, 7, 1), (1, 0, 1), (1, -7, 1),
            (1, 3661, 1), (1, float("nan"), 1), (1, float("inf"), 1),
            (1, 7, 0), (1, 7, -1), (1, 7, 1.5), (1, 7, 10001),
            (1, 7, float("nan")), (1, 7, float("inf")),
            ("", 7, 1), (None, 7, 1), (True, 7, 1), (1, True, 1), (1, 7, True),
        )
        for args in values:
            with self.subTest(args=args), self.assertRaises(SetupError):
                observed_monthly_traffic(*args)
        for unit, duration in (("months", 121), ("weeks", 1), (None, 1)):
            with self.subTest(unit=unit, duration=duration), self.assertRaises(SetupError):
                observed_monthly_traffic(1, duration, unit=unit)

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
