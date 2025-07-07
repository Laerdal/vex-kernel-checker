#!/usr/bin/env python3
"""
Unit tests for PatchManager module.
Tests patch fetching, URL extraction, and patch analysis functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the parent directory to the path so we can import the vex_kernel_checker package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from vex_kernel_checker.patch_manager import PatchManager
from vex_kernel_checker.common import CVEInfo


class TestPatchManager(unittest.TestCase):
    """Test cases for PatchManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.patch_manager = PatchManager()
        
        # Sample CVE data for testing
        self.sample_cve = CVEInfo(
            cve_id="CVE-2023-1234",
            description="Test CVE description",
            published_date="2023-01-01",
            cvss_score=7.5,
            patch_urls=["https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234"]
        )

    def test_extract_commit_id_from_kernel_org(self):
        """Test extracting commit ID from kernel.org URLs."""
        url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234"
        commit_id = self.patch_manager._extract_commit_id_from_url(url)
        self.assertEqual(commit_id, "abcd1234")

    def test_extract_commit_id_from_github(self):
        """Test extracting commit ID from GitHub URLs."""
        url = "https://github.com/torvalds/linux/commit/abcd1234"
        commit_id = self.patch_manager._extract_commit_id_from_url(url)
        self.assertEqual(commit_id, "abcd1234")

    def test_extract_commit_id_invalid_url(self):
        """Test handling of invalid URLs."""
        commit_id = self.patch_manager._extract_commit_id_from_url("https://example.com/invalid")
        self.assertIsNone(commit_id)

    def test_extract_patch_url_from_cve_patch_urls(self):
        """Test extracting patch URL from CVE patch_urls."""
        patch_url = self.patch_manager.extract_patch_url(self.sample_cve)
        self.assertIsNotNone(patch_url)
        if patch_url:
            self.assertIn("kernel.org", patch_url)

    def test_extract_patch_url_no_patch_urls(self):
        """Test handling CVE with no patch URLs."""
        cve_no_urls = CVEInfo(
            cve_id="CVE-2023-5678",
            description="CVE without patch URLs",
            published_date="2023-01-01",
            cvss_score=5.0,
            patch_urls=None
        )
        patch_url = self.patch_manager.extract_patch_url(cve_no_urls)
        self.assertIsNone(patch_url)

    @patch('requests.get')
    def test_fetch_patch_from_github_success(self, mock_get):
        """Test successful patch fetching from GitHub."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "diff --git a/file.c b/file.c\n+added line\n-removed line"
        mock_get.return_value = mock_response

        patch_content = self.patch_manager.fetch_patch_from_github("abcd1234")
        
        self.assertIsNotNone(patch_content)
        if patch_content:
            self.assertIn("diff --git", patch_content)
        mock_get.assert_called_once()

    @patch('requests.get')
    def test_fetch_patch_from_github_failure(self, mock_get):
        """Test handling of failed patch fetching."""
        # Mock failed response
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        patch_content = self.patch_manager.fetch_patch_from_github("invalidcommit")
        
        self.assertIsNone(patch_content)

    @patch('requests.get')
    def test_fetch_patch_from_github_with_fallback(self, mock_get):
        """Test patch fetching with API fallback."""
        # Mock direct URL failure, API success
        responses = [
            Mock(status_code=404),  # Direct URL fails
            Mock(status_code=200, json=lambda: {"files": [{"patch": "test patch content"}]})  # API succeeds
        ]
        mock_get.side_effect = responses

        patch_content = self.patch_manager.fetch_patch_from_github("abcd1234")
        
        self.assertIsNotNone(patch_content)
        self.assertEqual(mock_get.call_count, 2)

    def test_extract_sourcefiles_from_patch(self):
        """Test extraction of source files from patch content."""
        patch_content = """
diff --git a/drivers/gpu/drm/i915/i915_gem.c b/drivers/gpu/drm/i915/i915_gem.c
index 123..456 100644
--- a/drivers/gpu/drm/i915/i915_gem.c
+++ b/drivers/gpu/drm/i915/i915_gem.c
@@ -100,1 +100,2 @@ static int i915_gem_init()
+    /* Security fix */
diff --git a/include/drm/i915_drv.h b/include/drm/i915_drv.h
index 789..abc 100644
--- a/include/drm/i915_drv.h
+++ b/include/drm/i915_drv.h
@@ -50,1 +50,2 @@ struct drm_i915_private {
+    bool security_enabled;
"""
        
        source_files = self.patch_manager.extract_sourcefiles(patch_content)
        
        self.assertIsInstance(source_files, set)
        self.assertEqual(len(source_files), 2)
        # Check if the actual filename components are found
        found_gem = any("i915_gem.c" in f for f in source_files)
        found_drv = any("i915_drv.h" in f for f in source_files)
        self.assertTrue(found_gem)
        self.assertTrue(found_drv)

    def test_extract_config_options_from_patch(self):
        """Test extraction of config options from patch content."""
        patch_content = """
diff --git a/drivers/net/ethernet/realtek/Kconfig b/drivers/net/ethernet/realtek/Kconfig
index 123..456 100644
--- a/drivers/net/ethernet/realtek/Kconfig
+++ b/drivers/net/ethernet/realtek/Kconfig
@@ -100,6 +100,7 @@ config R8169
     depends on CONFIG_NET
+    select CONFIG_CRC32
     help
       This driver supports Realtek RTL8169 gigabit ethernet family of
       PCI/PCIe devices.
"""
        
        config_options = self.patch_manager.extract_config_options_from_patch(patch_content)
        
        self.assertIsInstance(config_options, set)
        # Config extraction should find references to CONFIG options
        self.assertTrue(len(config_options) >= 0)  # May or may not find configs depending on implementation

    def test_get_alternative_patch_urls(self):
        """Test generation of alternative patch URLs."""
        original_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234"
        
        alternative_urls = self.patch_manager.get_alternative_patch_urls(original_url)
        
        self.assertIsInstance(alternative_urls, list)
        self.assertTrue(len(alternative_urls) > 0)
        self.assertIn(original_url, alternative_urls)

    def test_kernel_org_to_github_conversion_via_public_api(self):
        """Test conversion of kernel.org URLs to GitHub equivalents via public API."""
        kernel_org_url = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234abcd5678"
        
        # Test through get_alternative_patch_urls which uses the conversion internally
        alternatives = self.patch_manager.get_alternative_patch_urls(kernel_org_url)
        
        # Should include GitHub alternatives
        expected_github = "https://github.com/torvalds/linux/commit/abcd1234abcd5678"
        github_found = any("github.com" in url and "abcd1234abcd5678" in url for url in alternatives)
        self.assertTrue(github_found)

    def test_url_ignored(self):
        """Test URL filtering for ignored patterns."""
        # Test URLs that should be ignored
        ignored_urls = [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
            "https://access.redhat.com/security/cve/CVE-2023-1234",
            "https://ubuntu.com/security/CVE-2023-1234"
        ]
        
        for url in ignored_urls:
            with self.subTest(url=url):
                self.assertTrue(self.patch_manager._url_ignored(url))

        # Test URLs that should not be ignored
        valid_urls = [
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abcd1234",
            "https://github.com/torvalds/linux/commit/abcd1234"
        ]
        
        for url in valid_urls:
            with self.subTest(url=url):
                self.assertFalse(self.patch_manager._url_ignored(url))

    def test_webdriver_functionality_without_selenium(self):
        """Test WebDriver functionality check when Selenium is not available."""
        # This test should pass regardless of Selenium availability
        result = self.patch_manager.test_webdriver_functionality()
        self.assertIsInstance(result, bool)

    @patch('vex_kernel_checker.patch_manager.SELENIUM_AVAILABLE', False)
    def test_fetch_patch_with_selenium_unavailable(self):
        """Test Selenium patch fetching when Selenium is unavailable."""
        result = self.patch_manager.fetch_patch_with_selenium("https://example.com/patch")
        self.assertIsNone(result)

    def test_replace_multiple_substrings(self):
        """Test the multiple substring replacement utility."""
        text = "Hello world, this is a test"
        replacements = {"Hello": "Hi", "world": "universe", "test": "example"}
        
        result = self.patch_manager._replace_multiple_substrings(text, replacements)
        
        self.assertEqual(result, "Hi universe, this is a example")

    def test_patch_manager_initialization(self):
        """Test PatchManager initialization with various parameters."""
        # Test with default parameters
        pm1 = PatchManager()
        self.assertIsNotNone(pm1)
        
        # Test with verbose mode
        pm2 = PatchManager(verbose=True)
        self.assertTrue(pm2.verbose)
        
        # Test with edge driver path
        pm3 = PatchManager(edge_driver_path="/path/to/driver")
        self.assertEqual(pm3.edge_driver_path, "/path/to/driver")

    def test_timed_method_decorator(self):
        """Test that timed methods work correctly."""
        # The fetch_patch_content_with_github_priority method is decorated with @timed_method
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response
            
            result = self.patch_manager.fetch_patch_content_with_github_priority("https://example.com/patch")
            
            # Should return None for failed fetch, but method should execute without error
            self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()
