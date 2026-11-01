"""Regression tests for public URL validation (no network required)."""

import socket
import unittest
from unittest.mock import patch

from scripts.url_utils import validate_url


PUBLIC_DNS = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


class ValidateUrlTests(unittest.TestCase):
    @patch("scripts.url_utils.socket.getaddrinfo", return_value=PUBLIC_DNS)
    def test_valid_urls_keep_original_form(self, lookup):
        for url, expected in [
            ("example.com", "https://example.com"),
            ("https://example.com/path", "https://example.com/path"),
            ("https://example.com:8443/path", "https://example.com:8443/path"),
        ]:
            with self.subTest(url=url):
                self.assertEqual(validate_url(url), expected)
        self.assertEqual(lookup.call_count, 3)

    @patch("scripts.url_utils.socket.getaddrinfo")
    def test_credentials_rejected_before_dns(self, lookup):
        for url in [
            "https://user:password@example.com/",
            "https://user@example.com/",
            "https://@example.com/",
            "https://:password@example.com/",
        ]:
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "embedded credentials"):
                    validate_url(url)
        lookup.assert_not_called()

    @patch("scripts.url_utils.socket.getaddrinfo")
    def test_invalid_ports_rejected_before_dns(self, lookup):
        for url in [
            "https://example.com:0/",
            "https://example.com:65536/",
            "https://example.com:notaport/",
            "https://example.com:-1/",
        ]:
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, "port"):
                    validate_url(url)
        lookup.assert_not_called()

    @patch("scripts.url_utils.socket.getaddrinfo", return_value=[])
    def test_empty_dns_response_fails_closed(self, lookup):
        with self.assertRaisesRegex(ValueError, "did not resolve"):
            validate_url("https://example.com/")

    @patch("scripts.url_utils.socket.getaddrinfo",
           return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))])
    def test_private_address_still_rejected(self, lookup):
        with self.assertRaisesRegex(ValueError, "blocked private/internal IP"):
            validate_url("https://example.com/")

    @patch("scripts.url_utils.socket.getaddrinfo", side_effect=socket.gaierror("unavailable"))
    def test_dns_errors_fail_closed(self, lookup):
        with self.assertRaisesRegex(ValueError, "DNS resolution failed"):
            validate_url("https://example.com/")


if __name__ == "__main__":
    unittest.main()
