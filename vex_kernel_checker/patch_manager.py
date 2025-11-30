"""
Patch management for VEX Kernel Checker.
"""

# flake8: noqa: SC200

import re
from typing import List, Optional, Set

import requests

# Selenium imports for web scraping
try:
    from selenium import webdriver
    from selenium.webdriver.edge.service import Service as EdgeService
    from selenium.webdriver.common.by import By

    # Remove unused imports
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    # Create dummy variables for fallback
    webdriver = None
    EdgeService = None
    By = None

from .base import VexKernelCheckerBase
from .common import timed_method


class PatchManager(VexKernelCheckerBase):
    """Manages patch fetching and processing from various sources."""

    def __init__(
        self,
        verbose: bool = False,
        edge_driver_path: Optional[str] = None,
        detailed_timing: bool = False,
        **kwargs,
    ):
        """Initialize patch manager."""
        super().__init__(
            verbose=verbose,
            detailed_timing=detailed_timing,
            edge_driver_path=edge_driver_path,
            **kwargs,
        )
        self.edge_driver_path = edge_driver_path

        # Compile regex patterns for patch processing
        self._config_patterns = self._compile_config_patterns()
        self._patch_patterns = self._compile_patch_patterns()

        if self.verbose:
            selenium_status = "available" if SELENIUM_AVAILABLE else "not available"
            driver_status = "configured" if self.edge_driver_path else "not configured"
            print(
                f"Patch Manager initialized - Selenium: {selenium_status}, WebDriver: {driver_status}"
            )

    def fetch_patch_with_selenium(self, patch_url: str) -> Optional[str]:
        """Fetch patch content using Selenium WebDriver with multiple fallback strategies."""
        if not SELENIUM_AVAILABLE:
            if self.verbose:
                print("Selenium not available, skipping WebDriver-based patch fetching")
            return None

        if not self.edge_driver_path:
            if self.verbose:
                print("Edge driver path not configured, skipping WebDriver-based patch fetching")
            return None

        # Try multiple alternative URLs
        urls_to_try = self.get_alternative_patch_urls(patch_url)

        for url in urls_to_try:
            if self.verbose:
                print(f"Attempting to fetch patch from: {url}")

            patch_content = self._fetch_patch_with_selenium_single(url)
            if patch_content:
                return patch_content

        return None

    def _fetch_patch_with_selenium_single(self, patch_url: str) -> Optional[str]:
        """Fetch patch content from a single URL using Selenium."""
        if not SELENIUM_AVAILABLE or not webdriver or not EdgeService or not By:
            return None

        if not self.edge_driver_path:
            return None

        driver = None
        try:
            service = EdgeService(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Edge(service=service, options=options)
            driver.set_page_load_timeout(30)

            if self.verbose:
                print(f"Loading patch URL: {patch_url}")

            driver.get(patch_url)

            # Try multiple selectors to find patch content
            selectors = [
                "pre.highlight",  # GitHub patch view
                "pre",  # Generic pre tag
                ".blob-code-inner",  # GitHub blob view
                ".file-diff-content",  # Generic diff content
                "table.diff-table",  # Table-based diff
                ".diff-content",  # Generic diff class
                "body",  # Last resort - entire body
            ]

            for selector in selectors:
                try:
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    content = element.text

                    if content and (
                        "diff --git" in content or "index " in content or "@@" in content
                    ):
                        if self.verbose:
                            print(
                                f"Successfully extracted patch content using selector: {selector}"
                            )
                        return content

                except Exception:
                    continue

            # If no specific selectors work, try the page source
            page_source = driver.page_source
            if page_source and ("diff --git" in page_source or "index " in page_source):
                if self.verbose:
                    print("Extracted patch content from page source")
                return page_source

            if self.verbose:
                print("No patch content found with any selector")
            return None

        except Exception as e:
            if self.verbose:
                print(f"WebDriver error for {patch_url}: {e}")
            return None
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass

    @timed_method
    def fetch_patch_content_with_github_priority(self, patch_url: str) -> Optional[str]:
        """Fetch patch content with GitHub API priority and multiple fallback methods."""
        if not patch_url:
            return None

        # Extract commit ID for GitHub API access
        commit_id = self._extract_commit_id_from_url(patch_url)

        # Try GitHub API first if commit ID is available (regardless of original URL source)
        if commit_id:
            github_content = self.fetch_patch_from_github(commit_id)
            if github_content:
                if self.verbose:
                    print("Successfully fetched patch from GitHub API")
                return github_content

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/plain, text/html, application/json, */*",
        }

        # Try alternative URLs (GitHub URLs will be prioritized in the list)
        alternative_urls = self.get_alternative_patch_urls(patch_url)
        if self.verbose:
            print(
                f"🔍 PatchManager: Found {len(alternative_urls)} alternative URLs for {patch_url}"
            )

        for alt_url in alternative_urls[:5]:  # Try top 5 alternatives
            if alt_url == patch_url:  # Skip original URL
                continue

            try:
                response = requests.get(alt_url, headers=headers, timeout=20)
                response.raise_for_status()

                content = response.text
                if content and ("diff --git" in content or "index " in content or "@@" in content):
                    if self.verbose:
                        print(f"Successfully fetched patch from alternative URL: {alt_url}")
                    return content

            except Exception as e:
                if self.verbose:
                    print(f"Alternative URL {alt_url} failed: {e}")
                continue

        # Try direct HTTP request to original URL
        try:
            if self.verbose:
                print(f"Attempting direct HTTP request to: {patch_url}")

            # Use the same headers as above for consistency

            response = requests.get(patch_url, headers=headers, timeout=30)
            response.raise_for_status()

            content = response.text
            if content and ("diff --git" in content or "index " in content or "@@" in content):
                if self.verbose:
                    print("Successfully fetched patch via direct HTTP")
                return content

        except Exception as e:
            if self.verbose:
                print(f"Direct HTTP request failed: {e}")

        # Final fallback: try Selenium WebDriver
        if SELENIUM_AVAILABLE and self.edge_driver_path:
            if self.verbose:
                print("Trying WebDriver as final fallback")
            return self.fetch_patch_with_selenium(patch_url)

        return None

    def fetch_patch_from_github(self, commit_id: str) -> Optional[str]:
        """Fetch patch content from GitHub API."""
        try:
            # Try direct GitHub patch URL first (this includes proper headers)
            github_patch_url = f"https://github.com/torvalds/linux/commit/{commit_id}.patch"

            response = requests.get(github_patch_url, timeout=30)
            if response.status_code == 200:
                content = response.text
                # Validate that it looks like a patch
                if content and ("diff --git" in content or "---" in content or "+++" in content):
                    return content

            # Fallback to API if direct patch URL doesn't work
            api_url = f"https://api.github.com/repos/torvalds/linux/commits/{commit_id}"
            response = requests.get(api_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                if "files" in data:
                    # Construct basic patch from API data
                    patch_lines = []
                    for file_data in data["files"]:
                        filename = file_data.get("filename", "unknown")
                        patch_lines.append(f"diff --git a/{filename} b/{filename}")
                        if "patch" in file_data:
                            patch_lines.append(file_data["patch"])
                    return "\n".join(patch_lines)

        except Exception:
            pass

        return None

    @timed_method
    def extract_sourcefiles(self, patch_info: str) -> Set[str]:
        """Extract source file paths from patch content."""
        source_files = set()

        if not patch_info:
            return source_files

        # Common patterns for file paths in patches
        patterns = [
            self._config_patterns[0],  # diff --git pattern
            re.compile(r"\+\+\+ b/(.*)"),  # +++ b/filename
            re.compile(r"--- a/(.*)"),  # --- a/filename
            re.compile(r"diff --git a/(.*) b/"),  # diff --git a/file b/file
        ]

        for line in patch_info.split("\n"):
            for pattern in patterns:
                matches = pattern.findall(line)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""

                    # Clean and validate the file path
                    clean_path = match.strip()
                    if clean_path and (
                        clean_path.endswith(".c")
                        or clean_path.endswith(".h")
                        or "Makefile" in clean_path
                    ):
                        # Apply path replacements
                        clean_path = self._replace_multiple_substrings(
                            clean_path, self.PATH_REPLACEMENTS
                        )
                        source_files.add(clean_path)

        if self.verbose and source_files:
            print(f"Extracted {len(source_files)} source files from patch")

        return source_files

    def get_alternative_patch_urls(self, original_url: str) -> List[str]:
        """Generate alternative patch URLs for better success rate, prioritizing GitHub."""
        alternatives = []

        # Extract commit ID if possible
        commit_id = self._extract_commit_id_from_url(original_url)
        if not commit_id:
            return alternatives

        # Check if this is a kernel.org stable/c URL and try to find GitHub equivalent
        github_url_from_kernel_org = self._convert_kernel_org_to_github(original_url, commit_id)

        # Prioritize GitHub URLs first (better API availability and reliability)
        github_templates = [
            f"https://github.com/torvalds/linux/commit/{commit_id}.patch",
            f"https://github.com/torvalds/linux/commit/{commit_id}.diff",
            f"https://github.com/torvalds/linux/commit/{commit_id}",
        ]

        # Add the converted GitHub URL at the very beginning if available and different
        if github_url_from_kernel_org and github_url_from_kernel_org not in github_templates:
            alternatives.append(github_url_from_kernel_org)

        # Add GitHub template URLs
        alternatives.extend(github_templates)

        # Then kernel.org URLs
        kernel_org_templates = [
            f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_id}",
            f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_id}",
            f"https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/patch/?id={commit_id}",
        ]

        # Add kernel.org templates
        alternatives.extend(kernel_org_templates)

        # Add the original URL only if it's not already included
        if original_url not in alternatives:
            alternatives.append(original_url)

        return alternatives

    def _extract_commit_id_from_url(self, url: str) -> Optional[str]:
        """Extract commit ID from various URL formats."""
        if not url:
            return None

        # Normalize URL to lowercase for consistent matching
        url = url.lower()

        # Common patterns for commit IDs in URLs
        patterns = [
            r"commit/([a-f0-9]{40})",  # GitHub commit
            r"commit/([a-f0-9]{8,40})",  # Shorter commit hashes
            r"id=([a-f0-9]{40})",  # kernel.org format
            r"id=([a-f0-9]{8,40})",  # kernel.org shorter
            r"/([a-f0-9]{40})\.patch",  # Direct patch format
            r"/([a-f0-9]{40})\.diff",  # Direct diff format
            r"/([a-f0-9]{40})",  # Direct commit format
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)

        return None

    def _convert_kernel_org_to_github(self, url: str, commit_id: str) -> Optional[str]:
        """Convert kernel.org URLs to GitHub equivalents when possible."""
        if "git.kernel.org" in url and commit_id:
            # Check if the GitHub URL exists with a simple HEAD request
            github_url = f"https://github.com/torvalds/linux/commit/{commit_id}.patch"
            try:
                response = requests.head(github_url, timeout=10)
                if response.status_code == 200:
                    if self.verbose:
                        print(f"Found GitHub equivalent for kernel.org URL: {github_url}")
                    return github_url
            except requests.RequestException:
                # If we can't check, that's fine - we'll try other URLs
                pass

        return None

    def _replace_multiple_substrings(self, text: str, replacements: dict) -> str:
        """Replace multiple substrings in text using a dictionary mapping."""
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def test_webdriver_functionality(self) -> bool:
        """Test WebDriver functionality."""
        if not SELENIUM_AVAILABLE:
            print("❌ Selenium not available")
            return False

        if not self.edge_driver_path:
            print("❌ Edge driver path not configured")
            return False

        if not webdriver or not EdgeService or not By:
            print("❌ Selenium components not properly imported")
            return False

        try:
            service = EdgeService(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")

            driver = webdriver.Edge(service=service, options=options)
            driver.set_page_load_timeout(10)

            # Test with a simple page
            driver.get("https://httpbin.org/get")

            # Check if we can find some content
            body = driver.find_element(By.TAG_NAME, "body")
            content = body.text

            driver.quit()

            if "httpbin.org" in content:
                print("✅ WebDriver functionality test passed")
                return True
            else:
                print("❌ WebDriver test failed - unexpected content")
                return False

        except Exception as e:
            print(f"❌ WebDriver test failed: {e}")
            return False

    def extract_patch_url(self, cve_info) -> Optional[str]:
        """Extract the best patch URL from CVE information, prioritizing GitHub."""
        if self.verbose:
            print("🔍 PatchManager: extract_patch_url called")

        if not cve_info.patch_urls:
            if self.verbose:
                print("🔍 PatchManager: No patch URLs found in CVE info")
            return None

        if self.verbose:
            print(
                f"🔍 PatchManager: Found {len(cve_info.patch_urls)} patch URLs: {cve_info.patch_urls}"
            )

        # Prioritize GitHub URLs first (better API availability and reliability)
        for url in cve_info.patch_urls:
            if self._url_ignored(url):
                if self.verbose:
                    print(f"🔍 PatchManager: Ignoring URL: {url}")
                continue

            if "github.com" in url:
                if self.verbose:
                    print(f"🔍 PatchManager: Selected GitHub URL: {url}")
                return url

        # Then try kernel.org URLs
        for url in cve_info.patch_urls:
            if self._url_ignored(url):
                continue

            if "git.kernel.org" in url:
                if self.verbose:
                    print(f"🔍 PatchManager: Selected kernel.org URL: {url}")
                return url

        # Fall back to any non-ignored URL
        for url in cve_info.patch_urls:
            if not self._url_ignored(url):
                if self.verbose:
                    print(f"🔍 PatchManager: Selected fallback URL: {url}")
                return url

        if self.verbose:
            print("🔍 PatchManager: All URLs were ignored, returning None")
        return None

    def _url_ignored(self, url: str) -> bool:
        """Check if a URL should be ignored for patch extraction."""
        ignored_patterns = [
            "cve.org",
            "mitre.org",
            "nvd.nist.gov",
            "ubuntu.com",
            "debian.org",
            "redhat.com",
            "suse.com",
        ]

        url_lower = url.lower()
        return any(pattern in url_lower for pattern in ignored_patterns)

    def extract_config_options_from_patch(self, patch_content: str) -> Set[str]:
        """Extract CONFIG_ options directly mentioned in patch content."""
        config_options = set()

        # Look for CONFIG_ options in patch content
        import re

        config_pattern = r"CONFIG_[A-Z0-9_]+"
        matches = re.findall(config_pattern, patch_content)

        for match in matches:
            config_options.add(match)
            if self.verbose:
                print(f"Found config option in patch: {match}")

        return config_options

    @timed_method
    def check_patch_presence(self, patch_content: str, kernel_source_path: str) -> bool:
        """
        Check if a security patch is already applied to the kernel source.

        Args:
            patch_content: The patch content (diff format)
            kernel_source_path: Path to the kernel source directory

        Returns:
            True if patch appears to be already applied, False if not applied
        """
        import os

        if not patch_content or not kernel_source_path:
            return False

        if not os.path.exists(kernel_source_path):
            if self.verbose:
                print(f"Kernel source path does not exist: {kernel_source_path}")
            return False

        # Extract the file changes from the patch
        patch_files = self._extract_patch_file_changes(patch_content)

        if not patch_files:
            if self.verbose:
                print("No file changes found in patch content")
            return False

        applied_count = 0
        total_count = 0

        for file_path, changes in patch_files.items():
            total_count += 1
            full_file_path = os.path.join(kernel_source_path, file_path)

            if not os.path.exists(full_file_path):
                if self.verbose:
                    print(f"File not found in kernel source: {file_path}")
                continue

            try:
                with open(full_file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()

                if self._check_changes_applied(file_content, changes):
                    applied_count += 1
                    if self.verbose:
                        print(f"✓ Patch changes appear applied in {file_path}")
                else:
                    if self.verbose:
                        print(f"✗ Patch changes NOT applied in {file_path}")

            except Exception as e:
                if self.verbose:
                    print(f"Error reading file {file_path}: {e}")
                continue

        # Consider patch applied if most files show the changes
        if total_count == 0:
            return False

        applied_ratio = applied_count / total_count
        is_applied = applied_ratio >= 0.5  # At least 50% of files show patch applied

        if self.verbose:
            print(
                f"Patch presence check: {applied_count}/{total_count} files show patch applied ({applied_ratio:.1%})"
            )
            print(f"Patch considered {'APPLIED' if is_applied else 'NOT APPLIED'}")

        return is_applied

    def check_all_patch_files_missing(self, patch_content: str, kernel_source_path: str) -> bool:
        """
        Check if ALL files from a patch are missing from the kernel source.

        This is a strong indicator that the vulnerable code is not present
        in this kernel version (e.g., driver added in a later kernel version,
        or architecture-specific code not present for this platform).

        Args:
            patch_content: The patch content
            kernel_source_path: Path to the kernel source directory

        Returns:
            True if ALL patched files are missing from the kernel source
        """
        import os

        if not patch_content or not kernel_source_path:
            return False

        if not os.path.exists(kernel_source_path):
            return False

        # Extract the file changes from the patch
        patch_files = self._extract_patch_file_changes(patch_content)

        if not patch_files:
            return False

        files_missing = 0
        total_files = len(patch_files)

        for file_path in patch_files.keys():
            full_file_path = os.path.join(kernel_source_path, file_path)
            if not os.path.exists(full_file_path):
                files_missing += 1

        # All files are missing - vulnerable code not present
        all_missing = files_missing == total_files

        if self.verbose and all_missing:
            print(
                f"⚠️  All {total_files} patched files are missing from kernel source - "
                "vulnerable code not present"
            )

        return all_missing

    def _extract_patch_file_changes(self, patch_content: str) -> dict:
        """
        Extract file changes from patch content.

        Returns:
            Dict mapping file paths to lists of added lines
        """
        import re

        file_changes = {}
        current_file = None

        lines = patch_content.split("\n")
        for line in lines:
            # Look for file headers
            if line.startswith("--- a/") or line.startswith("+++ b/"):
                if line.startswith("+++ b/"):
                    # Extract file path
                    current_file = line[6:].strip()
                    if current_file and not current_file.startswith("/dev/null"):
                        file_changes[current_file] = []

            # Look for added lines (security fixes)
            elif line.startswith("+") and current_file and not line.startswith("+++"):
                # Skip lines that are just additions of whitespace or comments
                stripped_line = line[1:].strip()
                if (
                    stripped_line
                    and not stripped_line.startswith("//")
                    and not stripped_line.startswith("/*")
                ):
                    file_changes[current_file].append(stripped_line)

        return file_changes

    def _check_changes_applied(self, file_content: str, added_lines: list) -> bool:
        """
        Check if the added lines from a patch are present in the file content.

        Args:
            file_content: Content of the source file
            added_lines: List of lines that were added by the patch

        Returns:
            True if most added lines are found in the file
        """
        if not added_lines:
            return True  # No changes to check

        found_count = 0
        for line in added_lines:
            # Look for the essence of the line (ignoring exact whitespace)
            line_essence = " ".join(line.split())
            if line_essence and line_essence in file_content:
                found_count += 1

        # Consider applied if at least 70% of added lines are found
        found_ratio = found_count / len(added_lines) if added_lines else 0
        return found_ratio >= 0.7
