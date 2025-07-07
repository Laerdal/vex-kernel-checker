"""
CVE data management for VEX Kernel Checker.
"""

import time
import requests
import threading
from typing import Optional, List

from .base import VexKernelCheckerBase
from .common import CVEInfo, timed_method, check_interrupt


class CVEDataManager(VexKernelCheckerBase):
    """Manages CVE data fetching and processing."""
    
    # Class-level thread-safe rate limiting for NVD API calls
    _api_rate_lock = threading.Lock()
    _last_global_api_call = 0.0
    
    def __init__(self, verbose: bool = False, api_key: Optional[str] = None, 
                 detailed_timing: bool = False, **kwargs):
        """Initialize CVE data manager."""
        super().__init__(verbose=verbose, detailed_timing=detailed_timing, **kwargs)
        self.api_key = api_key
        
        if self.verbose:
            api_status = "provided" if self.api_key else "not provided (rate limited)"
            print(f"CVE Data Manager initialized - API key: {api_status}")

    def is_kernel_related_cve(self, cve_info: CVEInfo) -> bool:
        """Check if a CVE is related to the Linux kernel."""
        if not cve_info or not cve_info.description:
            return False
        
        description = cve_info.description.lower()
        kernel_keywords = [
            'linux kernel', 'kernel', 'linux', 'driver', 'subsystem',
            'filesystem', 'networking', 'memory management', 'scheduler',
            'security module', 'kernel module', 'device driver',
            'kernel space', 'syscall', 'system call'
        ]
        
        return any(keyword in description for keyword in kernel_keywords)

    @timed_method
    def fetch_cve_details(self, cve_id: str) -> Optional[CVEInfo]:
        """Fetch CVE details from NVD API with rate limiting and caching."""
        if self.verbose:
            print(f"🔍 CVE Manager: fetch_cve_details called for {cve_id}")
        
        # Check for interrupt before starting
        check_interrupt()
        
        # Check cache first
        cache_key = f"cve_{cve_id}"
        if cache_key in self._config_cache:
            if self.verbose:
                print(f"🔍 CVE Manager: Found {cve_id} in cache, returning cached data")
            self._record_cache_hit('config')
            return self._config_cache[cache_key]

        if self.verbose:
            print(f"🔍 CVE Manager: {cve_id} not in cache, will fetch from NVD API")
        self._record_cache_miss('config')

        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {'cveId': cve_id}
        
        if self.api_key:
            headers = {'apiKey': self.api_key}
        else:
            headers = {}

        for attempt in range(self.API_MAX_RETRIES):
            check_interrupt()  # Check for interrupt before each attempt
            
            try:
                if self.verbose:
                    print(f"Fetching CVE details for {cve_id} from NVD API (attempt {attempt + 1})")
                
                response = requests.get(base_url, params=params, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if 'vulnerabilities' in data and data['vulnerabilities']:
                        vuln_data = data['vulnerabilities'][0]['cve']
                        
                        # Extract CVE information
                        cve_info = CVEInfo(
                            cve_id=cve_id,
                            description=vuln_data.get('descriptions', [{}])[0].get('value', ''),
                            published_date=vuln_data.get('published', ''),
                            modified_date=vuln_data.get('lastModified', '')
                        )
                        
                        # Extract severity and CVSS if available
                        metrics = vuln_data.get('metrics', {})
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cve_info.cvss_score = cvss_data.get('baseScore')
                            cve_info.severity = cvss_data.get('baseSeverity', '').upper()
                        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cve_info.cvss_score = cvss_data.get('baseScore')
                            cve_info.severity = cvss_data.get('baseSeverity', '').upper()
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            cve_info.cvss_score = cvss_data.get('baseScore')
                            # Map CVSS v2 severity
                            score = cvss_data.get('baseScore', 0)
                            if score >= 7.0:
                                cve_info.severity = 'HIGH'
                            elif score >= 4.0:
                                cve_info.severity = 'MEDIUM'
                            else:
                                cve_info.severity = 'LOW'
                        
                        # Extract patch URLs from references
                        patch_urls = []
                        references = vuln_data.get('references', [])
                        for ref in references:
                            url = ref.get('url', '')
                            if any(domain in url for domain in ['git.kernel.org', 'github.com', 'gitlab.com']):
                                patch_urls.append(url)
                        
                        cve_info.patch_urls = patch_urls
                        
                        # Cache the result
                        self._config_cache[cache_key] = cve_info
                        
                        if self.verbose:
                            print(f"Successfully fetched CVE details for {cve_id}")
                        
                        return cve_info
                    else:
                        if self.verbose:
                            print(f"No CVE data found for {cve_id}")
                        return None
                
                elif response.status_code == 429:  # Rate limited
                    backoff_time = self.API_BACKOFF_FACTOR ** attempt
                    if self.verbose:
                        print(f"Rate limited by NVD API, backing off for {backoff_time}s")
                    self._interruptible_sleep(backoff_time)
                    continue
                
                elif response.status_code == 404:
                    if self.verbose:
                        print(f"CVE {cve_id} not found in NVD")
                    return None
                
                else:
                    if self.verbose:
                        print(f"NVD API error {response.status_code}: {response.text}")
                    
                    if attempt < self.API_MAX_RETRIES - 1:
                        backoff_time = self.API_BACKOFF_FACTOR ** attempt
                        self._interruptible_sleep(backoff_time)
                        continue
                    else:
                        return None
                        
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"Network error fetching CVE {cve_id}: {e}")
                
                if attempt < self.API_MAX_RETRIES - 1:
                    backoff_time = self.API_BACKOFF_FACTOR ** attempt
                    self._interruptible_sleep(backoff_time)
                    continue
                else:
                    return None
        
        return None

    def _interruptible_sleep(self, duration: float):
        """Sleep for the given duration, but allow for interrupts."""
        chunks = int(duration / 0.5) + 1
        chunk_duration = duration / chunks
        
        for _ in range(chunks):
            time.sleep(chunk_duration)
            check_interrupt()

    def extract_patch_url(self, cve_info: CVEInfo) -> Optional[str]:
        """Extract the best patch URL from CVE information, prioritizing GitHub."""
        if not cve_info.patch_urls:
            return None
        
        # Prioritize GitHub URLs first (better API availability and reliability)
        for url in cve_info.patch_urls:
            if self._url_ignored(url):
                continue
                
            if 'github.com' in url:
                return url
        
        # Then try kernel.org URLs
        for url in cve_info.patch_urls:
            if self._url_ignored(url):
                continue
                
            if 'git.kernel.org' in url:
                return url
        
        # Fall back to any non-ignored URL
        for url in cve_info.patch_urls:
            if not self._url_ignored(url):
                return url
        
        return None

    def _url_ignored(self, url: str) -> bool:
        """Check if URL should be ignored based on domain patterns."""
        return any(ignored_domain in url for ignored_domain in self.IGNORED_URLS)

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
        import re
        
        # Common patterns for commit IDs in URLs
        patterns = [
            r'commit/([a-f0-9]{40})',  # GitHub commit
            r'commit/([a-f0-9]{8,40})',  # Shorter commit hashes
            r'id=([a-f0-9]{40})',  # kernel.org format
            r'id=([a-f0-9]{8,40})',  # kernel.org shorter
            r'/([a-f0-9]{40})\.patch',  # Direct patch format
            r'/([a-f0-9]{40})\.diff',  # Direct diff format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return match.group(1)
        
        return None

    def _convert_kernel_org_to_github(self, url: str, commit_id: str) -> Optional[str]:
        """Convert kernel.org URLs to GitHub equivalents when possible."""
        if 'git.kernel.org' in url and commit_id:
            # Try to convert to GitHub format
            return f"https://github.com/torvalds/linux/commit/{commit_id}.patch"
        return None
