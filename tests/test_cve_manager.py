#!/usr/bin/env python3
"""
Unit tests for VEX Kernel Checker CVE Manager.

Tests CVE data fetching, caching, and management.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock, Mock
import requests

from vex_kernel_checker.cve_manager import CVEDataManager
from vex_kernel_checker.common import CVEInfo


class TestCVEDataManager(unittest.TestCase):
    """Test cases for CVEDataManager class."""

    def setUp(self):
        """Set up test fixtures."""
        # Initialize manager without API key (rate limited mode)
        self.manager = CVEDataManager(verbose=False)

        # Initialize manager with API key
        self.manager_with_key = CVEDataManager(verbose=False, api_key="test-api-key-12345")

    def test_initialization_without_api_key(self):
        """Test initialization without API key."""
        manager = CVEDataManager(verbose=False)

        self.assertFalse(manager.verbose)
        self.assertIsNone(manager.api_key)

    def test_initialization_with_api_key(self):
        """Test initialization with API key."""
        manager = CVEDataManager(verbose=False, api_key="test-key")

        self.assertEqual(manager.api_key, "test-key")

    def test_is_kernel_related_cve_positive_cases(self):
        """Test kernel-related CVE detection - positive cases."""
        kernel_cve_infos = [
            CVEInfo(cve_id="CVE-1", description="Linux kernel vulnerability in the driver"),
            CVEInfo(
                cve_id="CVE-2",
                description="Issue in kernel module affecting network stack",
            ),
            CVEInfo(cve_id="CVE-3", description="Buffer overflow in linux filesystem"),
            CVEInfo(
                cve_id="CVE-4",
                description="Vulnerability affecting the scheduler subsystem",
            ),
        ]

        for cve_info in kernel_cve_infos:
            with self.subTest(cve_id=cve_info.cve_id):
                self.assertTrue(self.manager.is_kernel_related_cve(cve_info))

    def test_is_kernel_related_cve_negative_cases(self):
        """Test kernel-related CVE detection - negative cases."""
        non_kernel_cve_infos = [
            CVEInfo(cve_id="CVE-1", description="Vulnerability in Apache web server"),
            CVEInfo(cve_id="CVE-2", description="Issue in Node.js application"),
            CVEInfo(cve_id="CVE-3", description="Buffer overflow in user application"),
            CVEInfo(cve_id="CVE-4", description="Database authentication bypass"),
        ]

        for cve_info in non_kernel_cve_infos:
            with self.subTest(cve_id=cve_info.cve_id):
                self.assertFalse(self.manager.is_kernel_related_cve(cve_info))

    def test_is_kernel_related_cve_none_cases(self):
        """Test kernel-related CVE detection with None or empty data."""
        # Test with no description
        empty_cve = CVEInfo(cve_id="CVE-EMPTY")
        self.assertFalse(self.manager.is_kernel_related_cve(empty_cve))

        # Test with empty description
        empty_desc_cve = CVEInfo(cve_id="CVE-EMPTY-DESC", description="")
        self.assertFalse(self.manager.is_kernel_related_cve(empty_desc_cve))

    def test_extract_patch_url_with_github_urls(self):
        """Test extracting patch URLs from CVE info."""
        # Create CVE with GitHub URLs in patch_urls field
        cve_info = CVEInfo(
            cve_id="CVE-2023-12345",
            patch_urls=[
                "https://github.com/torvalds/linux/commit/abc123def456",
                "https://github.com/torvalds/linux/commit/789xyz",
            ],
        )

        patch_url = self.manager.extract_patch_url(cve_info)

        # Should return the first GitHub commit URL found
        self.assertEqual(patch_url, "https://github.com/torvalds/linux/commit/abc123def456")

    def test_extract_patch_url_no_urls(self):
        """Test extracting patch URLs when none exist."""
        cve_info = CVEInfo(
            cve_id="CVE-2023-12345",
            description="A vulnerability exists in the driver without any GitHub links.",
        )

        patch_url = self.manager.extract_patch_url(cve_info)
        self.assertIsNone(patch_url)

    def test_extract_patch_url_with_patch_urls_field(self):
        """Test extracting patch URLs from patch_urls field."""
        cve_info = CVEInfo(
            cve_id="CVE-2023-12345",
            description="A vulnerability in the driver",
            patch_urls=["https://github.com/torvalds/linux/commit/fix123"],
        )

        patch_url = self.manager.extract_patch_url(cve_info)
        self.assertEqual(patch_url, "https://github.com/torvalds/linux/commit/fix123")

    def test_get_alternative_patch_urls(self):
        """Test generating alternative patch URLs."""
        original_url = "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=abc123def456"

        alternatives = self.manager.get_alternative_patch_urls(original_url)

        # Should include GitHub alternatives
        expected_github = "https://github.com/torvalds/linux/commit/abc123def456"
        self.assertIn(expected_github, alternatives)

        # Should include patch format
        expected_patch = "https://github.com/torvalds/linux/commit/abc123def456.patch"
        self.assertIn(expected_patch, alternatives)

    @patch("requests.get")
    def test_fetch_cve_details_success(self, mock_get):
        """Test successful CVE details fetching."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [{"lang": "en", "value": "Linux kernel vulnerability"}],
                        "published": "2023-01-01T00:00:00.000",
                        "lastModified": "2023-01-02T00:00:00.000",
                        "metrics": {
                            "cvssMetricV3": [
                                {"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}
                            ]
                        },
                    }
                }
            ]
        }
        mock_get.return_value = mock_response

        cve_info = self.manager.fetch_cve_details("CVE-2023-12345")

        self.assertIsNotNone(cve_info)
        if cve_info:  # Type guard for mypy
            self.assertIsInstance(cve_info, CVEInfo)
            self.assertEqual(cve_info.cve_id, "CVE-2023-12345")
            self.assertEqual(cve_info.description, "Linux kernel vulnerability")

    @patch("requests.get")
    def test_fetch_cve_details_api_error(self, mock_get):
        """Test CVE details fetching with API error."""
        # Mock API error response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_get.return_value = mock_response

        cve_info = self.manager.fetch_cve_details("CVE-NONEXISTENT")

        self.assertIsNone(cve_info)

    @patch("requests.get")
    def test_fetch_cve_details_network_error(self, mock_get):
        """Test CVE details fetching with network error."""
        # Mock network error
        mock_get.side_effect = requests.exceptions.RequestException("Network error")

        cve_info = self.manager.fetch_cve_details("CVE-2023-12345")

        self.assertIsNone(cve_info)

    def test_url_handling(self):
        """Test URL handling via public API."""
        # Test extract_patch_url which uses internal URL filtering
        cve_info = CVEInfo(
            cve_id="CVE-2023-12345",
            patch_urls=[
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345",  # Should be ignored
                "https://github.com/torvalds/linux/commit/abc123",  # Should be used
            ],
        )

        patch_url = self.manager.extract_patch_url(cve_info)
        # Should return the GitHub URL, not the CVE MITRE URL
        self.assertEqual(patch_url, "https://github.com/torvalds/linux/commit/abc123")


if __name__ == "__main__":
    unittest.main(verbosity=2)
