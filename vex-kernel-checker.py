#!/usr/bin/env python3
"""
VEX Kernel Checker - A tool for analyzing CVE vulnerabilities against kernel configurations.

This script processes VEX (Vulnerability Exploitability eXchange) files and checks
whether CVEs are applicable to a given kernel configuration by analyzing patch files
and Makefile configurations.

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import argparse
import json
import os
import re
import requests
import time
import glob
import traceback
import functools
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union
from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import SessionNotCreatedException, WebDriverException, TimeoutException, NoSuchElementException

# Performance tracking utilities
def timed_method(func):
    """Decorator to track method execution time."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time
        
        # Get class name if this is a method
        class_name = ""
        if args and hasattr(args[0], '__class__'):
            class_name = args[0].__class__.__name__ + "."
        
        print(f"⏱️  {class_name}{func.__name__}: {duration:.3f}s")
        return result
    return wrapper

class PerformanceTracker:
    """Track performance metrics across the application."""
    
    def __init__(self):
        self.timings = {}
        self.cache_stats = {}
    
    def start_timer(self, name: str):
        """Start a named timer."""
        self.timings[name] = {'start': time.time()}
    
    def end_timer(self, name: str):
        """End a named timer and record duration."""
        if name in self.timings and 'start' in self.timings[name]:
            self.timings[name]['duration'] = time.time() - self.timings[name]['start']
    
    def record_cache_hit(self, cache_name: str):
        """Record a cache hit."""
        if cache_name not in self.cache_stats:
            self.cache_stats[cache_name] = {'hits': 0, 'misses': 0}
        self.cache_stats[cache_name]['hits'] += 1
    
    def record_cache_miss(self, cache_name: str):
        """Record a cache miss."""
        if cache_name not in self.cache_stats:
            self.cache_stats[cache_name] = {'hits': 0, 'misses': 0}
        self.cache_stats[cache_name]['misses'] += 1
    
    def print_summary(self):
        """Print performance summary."""
        print("\n" + "="*60)
        print("🚀 PERFORMANCE SUMMARY")
        print("="*60)
        
        if self.timings:
            print("\n⏱️  TIMING RESULTS:")
            for name, data in sorted(self.timings.items()):
                if 'duration' in data:
                    print(f"  {name}: {data['duration']:.3f}s")
        
        if self.cache_stats:
            print("\n💾 CACHE PERFORMANCE:")
            total_hits = total_requests = 0
            for cache_name, stats in sorted(self.cache_stats.items()):
                hits = stats['hits']
                misses = stats['misses']
                total = hits + misses
                hit_rate = (hits / total * 100) if total > 0 else 0
                
                total_hits += hits
                total_requests += total
                
                print(f"  {cache_name}:")
                print(f"    Hits: {hits}, Misses: {misses}, Hit Rate: {hit_rate:.1f}%")
            
            if total_requests > 0:
                overall_hit_rate = (total_hits / total_requests * 100)
                print(f"\n  Overall Cache Hit Rate: {overall_hit_rate:.1f}%")
        
        print("="*60)

# Global performance tracker
perf_tracker = PerformanceTracker()

class VulnerabilityState(Enum):
    """Enumeration of possible vulnerability analysis states."""
    NOT_AFFECTED = "not_affected"
    AFFECTED = "affected"
    UNDER_INVESTIGATION = "under_investigation"
    

class Justification(Enum):
    """Enumeration of justification reasons for vulnerability state."""
    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"


@dataclass
class VulnerabilityAnalysis:
    """Data class representing a vulnerability analysis result."""
    state: VulnerabilityState
    justification: Optional[Justification] = None
    detail: Optional[str] = None
    response: Optional[List[str]] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary format for VEX output."""
        result = {"state": self.state.value}
        if self.justification:
            result["justification"] = self.justification.value
        if self.detail:
            result["detail"] = self.detail
        if self.response:
            result["response"] = self.response
        if self.timestamp:
            result["timestamp"] = self.timestamp
        return result


@dataclass
class CVEInfo:
    """Enhanced CVE information structure."""
    
    def __init__(self, cve_id: str, severity: Optional[str] = None, cvss_score: Optional[float] = None,
                 description: Optional[str] = None, published_date: Optional[str] = None,
                 last_modified: Optional[str] = None, patch_urls: Optional[List[str]] = None):
        self.cve_id = cve_id
        self.severity = severity
        self.cvss_score = cvss_score
        self.description = description
        self.published_date = published_date
        self.last_modified = last_modified
        self.patch_urls = patch_urls if patch_urls is not None else []


class VexKernelChecker:
    """Enhanced VEX Kernel Checker for robust vulnerability analysis.
    
    This tool analyzes CVE vulnerabilities against kernel configurations using:
    - Advanced Makefile/Kbuild parsing with pattern recognition
    - Recursive include processing and variable expansion  
    - Kconfig dependency analysis for transitive requirements
    - Multi-strategy configuration option detection
    - Comprehensive WebDriver error handling and validation
    - Detailed vulnerability reporting and validation
    
    Key Features:
    - MIT Licensed with comprehensive error handling
    - Supports complex Makefile patterns and conditional compilation
    - Analyzes source files for configuration hints (#ifdef, IS_ENABLED)
    - Handles composite objects, multi-line assignments, and variable expansions
    - Provides detailed diagnostics and testing capabilities
    - Follows kernel subsystem conventions for configuration inference
    """
    
    # Class-level thread-safe rate limiting for NVD API calls
    _api_rate_lock = threading.Lock()
    _last_global_api_call = 0.0
    
    # Class constants
    IGNORED_URLS = {
        "https://codereview.qt-project.org",
        "https://github.com/qt",
        "https://www.qt.io/"
    }
    
    ENABLED_DEFAULT_OPTIONS = {
        "CONFIG_NET",
        "CONFIG_BT", 
        "CONFIG_GENERIC_PHY",
        "CONFIG_SND_SOC"
    }
    
    PATH_REPLACEMENTS = {
        "b//": "",
        "smb/client": "cifs",
        "smb/server": "ksmbd",
        "net/wireless/silabs": "staging"
    }
    
    # Rate limiting for API calls (increased for better reliability)
    API_RATE_LIMIT_DELAY = 1.5  # seconds between API calls (NVD API requires 3+ second delays)
    API_MAX_RETRIES = 3  # Maximum number of retries for API calls
    API_BACKOFF_FACTOR = 2.0  # Exponential backoff factor
    
    # Further reduced concurrency to prevent API rate limiting issues
    MAX_PARALLEL_WORKERS = 2  # Further reduced to prevent NVD API rate limiting
    MAKEFILE_CACHE_SIZE = 5000  # Increased from 2000 for better hit rate
    CONFIG_CACHE_SIZE = 2000  # Increased from 1000 for better hit rate
    SOURCE_ANALYSIS_CACHE_SIZE = 1000  # New cache for source file analysis
    
    # Optimized search limits for performance
    MAX_MAKEFILE_SEARCH_FILES = 100  # Reduced from 200 to focus on most relevant files
    MAX_KCONFIG_RECURSION_DEPTH = 20  # Reduced from 50 to prevent deep recursion
    MAX_INCLUDE_FILES_PER_MAKEFILE = 5  # Reduced from 10 to limit processing scope
    
    # New performance optimization flags
    ENABLE_AGGRESSIVE_CACHING = True
    ENABLE_PARALLEL_FILE_IO = True
    ENABLE_SMART_SEARCH_ORDERING = True
    
    def __init__(self, verbose: bool = False, api_key: str = None, edge_driver_path: str = None, disable_patch_checking: bool = False, analyze_all_cves: bool = False):
        """Initialize the VEX Kernel Checker.
        
        Args:
            verbose: Enable verbose logging
            api_key: NVD API key for fetching CVE details (optional, will disable web-based patch fetching if not provided)
            edge_driver_path: Path to Edge WebDriver executable (optional, will disable web-based patch fetching if not provided)
            disable_patch_checking: Explicitly disable patch checking (for config-only analysis)
            analyze_all_cves: Analyze all CVEs regardless of kernel relevance (default: only analyze kernel-related CVEs)
        """
        self.verbose = verbose
        self.api_key = api_key
        self.edge_driver_path = edge_driver_path
        self.last_api_call = 0.0
        self._processed_cves = set()  # Track processed CVEs to avoid duplicates
        self.analyze_all_cves = analyze_all_cves  # Flag for controlling CVE filtering
        
        # Determine patch checking capability
        if disable_patch_checking:
            self.check_patches = False
            if self.verbose:
                print("Patch checking explicitly disabled - config-only analysis mode")
        elif not api_key or not edge_driver_path:
            self.check_patches = False
            if self.verbose:
                print("Patch checking disabled - missing API key or WebDriver (will attempt config-only analysis)")
        else:
            self.check_patches = True
            if self.verbose:
                print("Patch checking enabled - full CVE analysis mode")
        
        # Performance optimization caches
        self._makefile_cache = {}  # Cache for parsed Makefile content
        self._config_cache = {}  # Cache for resolved configuration options
        self._kconfig_cache = {}  # Cache for Kconfig dependencies
        self._path_cache = {}  # Cache for path-based inference results
        
        # New advanced performance caches
        self._source_analysis_cache = {}  # Cache for source file analysis results
        self._directory_priority_cache = {}  # Cache for directory search prioritization
        self._makefile_location_cache = {}  # Cache for makefile locations
        
        # Precompiled regex patterns for ultra-fast pattern matching
        self._advanced_config_patterns = self._compile_advanced_config_patterns()
        self._optimized_source_patterns = self._compile_optimized_source_patterns()
        self._patch_patterns = self._compile_patch_patterns()
        
        # Performance tracking
        # Performance tracking
        self._cache_hits = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        self._cache_misses = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        
        # File content cache for ultra-fast I/O
        self._file_content_cache = {}

    def _get_cached_file_content(self, file_path: str) -> str:
        """Get file content with caching for ultra-fast I/O."""
        if file_path in self._file_content_cache:
            return self._file_content_cache[file_path]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Cache the content with size limit
            if len(self._file_content_cache) < 1000:  # Limit cache size
                self._file_content_cache[file_path] = content
            
            return content
        except Exception:
            return ""

    def _get_cached_makefile_vars(self, makefile_path: str) -> Dict[str, str]:
        """Get Makefile variables with caching."""
        cache_key = f"vars:{makefile_path}"
        if cache_key in self._makefile_cache:
            return self._makefile_cache[cache_key]
        
        variables = {}
        try:
            content = self._get_cached_file_content(makefile_path)
            if content:
                # Extract variable assignments (VAR = value or VAR := value)
                var_pattern = re.compile(r'^([A-Z_][A-Z0-9_]*)\s*[:+]?=\s*(.*)$', re.MULTILINE)
                for match in var_pattern.finditer(content):
                    var_name = match.group(1)
                    var_value = match.group(2).strip()
                    variables[var_name] = var_value
            
            # Cache the variables
            self._makefile_cache[cache_key] = variables
        except Exception:
            pass
        
        return variables

    def clear_all_caches(self):
        """Clear all internal caches to start fresh analysis.
        
        This method clears all the performance caches including:
        - Makefile parsing cache
        - Configuration option cache
        - Kconfig dependencies cache
        - Path-based inference cache
        - Source file analysis cache
        - Directory prioritization cache
        - Makefile location cache
        - File content cache
        """
        cache_sizes_before = {
            'makefile': len(self._makefile_cache),
            'config': len(self._config_cache),
            'kconfig': len(self._kconfig_cache),
            'path': len(self._path_cache),
            'source_analysis': len(self._source_analysis_cache),
            'directory_priority': len(self._directory_priority_cache),
            'makefile_location': len(self._makefile_location_cache),
            'file_content': len(self._file_content_cache)
        }
        
        # Clear all caches
        self._makefile_cache.clear()
        self._config_cache.clear()
        self._kconfig_cache.clear()
        self._path_cache.clear()
        self._source_analysis_cache.clear()
        self._directory_priority_cache.clear()
        self._makefile_location_cache.clear()
        self._file_content_cache.clear()
        
        # Reset cache statistics
        self._cache_hits = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        self._cache_misses = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        
        if self.verbose:
            total_entries = sum(cache_sizes_before.values())
            print(f"Cleared all caches - removed {total_entries} cached entries:")
            for cache_name, size in cache_sizes_before.items():
                if size > 0:
                    print(f"  - {cache_name}: {size} entries")

    @staticmethod
    def validate_file_path(file_path: str) -> str:
        """Validate that a file exists at the given path."""
        if not os.path.isfile(file_path):
            raise argparse.ArgumentTypeError(f"File not found: {file_path}")
        return file_path

    @staticmethod
    def validate_directory_path(dir_path: str) -> str:
        """Validate that a directory exists at the given path."""
        if not os.path.isdir(dir_path):
            raise argparse.ArgumentTypeError(f"Directory not found: {dir_path}")
        return dir_path

    @staticmethod
    def validate_api_key(api_key: str) -> str:
        """Validate API key format."""
        if not re.match(r'^[a-f0-9-]{36}$', api_key):
            raise argparse.ArgumentTypeError("Invalid API key format")
        return api_key

    @staticmethod
    def validate_edge_driver_path(driver_path: str) -> str:
        """Validate Edge WebDriver path with enhanced checks."""
        if not os.path.isfile(driver_path):
            raise argparse.ArgumentTypeError(f"Edge WebDriver not found: {driver_path}")
        
        # Check if file is executable (on Unix-like systems)
        if hasattr(os, 'access') and not os.access(driver_path, os.X_OK):
            print(f"Warning: WebDriver file may not be executable: {driver_path}")
            print("You may need to run: chmod +x {driver_path}")
        
        # Basic validation of file name
        filename = os.path.basename(driver_path).lower()
        if 'edge' not in filename and 'msedge' not in filename:
            print(f"Warning: File name doesn't appear to be an Edge WebDriver: {filename}")
            print("Expected names include: msedgedriver, edgedriver, etc.")
        
        return driver_path

    @staticmethod
    def load_vex_file(file_path: str) -> Dict:
        """Load VEX file from JSON."""
        print(f"Loading VEX file from {file_path}...")
        with open(file_path, 'r') as file:
            return json.load(file)

    @staticmethod
    def load_kernel_config(config_path: str) -> List[str]:
        """Load kernel configuration and extract enabled options."""
        print(f"Loading kernel configuration from {config_path}...")
        strip_patterns = {"=m": "", "=y": ""}
        
        with open(config_path, 'r') as file:
            enabled_options = []
            for line in file:
                line = line.strip()
                if line.endswith('=y') or line.endswith('=m'):
                    cleaned_line = VexKernelChecker._replace_multiple_substrings(line, strip_patterns)
                    enabled_options.append(cleaned_line)
            return enabled_options

    @staticmethod
    def _replace_multiple_substrings(text: str, replacements: Dict[str, str]) -> str:
        """Replace multiple substrings in text based on replacement dictionary."""
        pattern = re.compile("|".join(re.escape(key) for key in replacements.keys()))
        return pattern.sub(lambda match: replacements[match.group(0)], text)

    def is_kernel_related_cve(self, cve_info: CVEInfo) -> bool:
        """Determine if a CVE is related to the Linux kernel.
        
        This method analyzes various aspects of the CVE to determine if it's
        kernel-related, including:
        - CVE description text
        - Patch URLs pointing to kernel repositories
        - Reference URLs and tags
        
        Args:
            cve_info: CVE information object
            
        Returns:
            True if the CVE appears to be kernel-related, False otherwise
        """
        if not cve_info:
            return False
        
        # Check description for kernel-related keywords
        description = cve_info.description.lower() if cve_info.description else ""
        
        # Strong kernel indicators in description
        kernel_keywords = [
            'linux kernel', 'kernel', 'vmlinux', 'kmod', 'ksymtab',
            'syscall', 'system call', 'kernel module', 'kernel space',
            'kernel driver', 'kernel panic', 'kernel oops', 'kernel crash',
            'kernel memory', 'kernel buffer', 'kernel stack', 'kernel heap',
            'kernel thread', 'kernel process', 'kernel scheduler',
            'kernel filesystem', 'kernel network', 'kernel security',
            'kernel vulnerability', 'kernel bug', 'kernel fix',
            'kernel patch', 'kernel source', 'kernel code',
            'kernel implementation', 'kernel subsystem',
            'device driver', 'kernel api', 'kernel function',
            'kernel data structure', 'kernel interface'
        ]
        
        # Check for kernel keywords in description
        if any(keyword in description for keyword in kernel_keywords):
            if self.verbose:
                print(f"CVE {cve_info.cve_id} identified as kernel-related based on description keywords")
            return True
        
        # Check patch URLs for kernel repositories
        if cve_info.patch_urls:
            kernel_repo_indicators = [
                'git.kernel.org',
                'github.com/torvalds/linux',
                'lore.kernel.org',
                'patchwork.kernel.org',
                'kernel.org',
                'linux-kernel',
                'stable/linux'
            ]
            
            for patch_url in cve_info.patch_urls:
                if any(indicator in patch_url.lower() for indicator in kernel_repo_indicators):
                    if self.verbose:
                        print(f"CVE {cve_info.cve_id} identified as kernel-related based on patch URL: {patch_url}")
                    return True
        
        # Additional heuristics based on CVE ID patterns
        # Some CVE databases have patterns for kernel CVEs
        cve_id = cve_info.cve_id
        
        # If we have patch URLs but none are clearly kernel-related,
        # and description doesn't contain kernel keywords, likely not kernel-related
        if cve_info.patch_urls and not any(keyword in description for keyword in [
            'linux', 'kernel', 'driver', 'syscall', 'module'
        ]):
            # Check for non-kernel indicators
            non_kernel_indicators = [
                'apache', 'nginx', 'mysql', 'postgresql', 'mongodb',
                'nodejs', 'python', 'java', 'php', 'ruby', 'perl',
                'docker', 'kubernetes', 'openssl', 'gnutls',
                'firefox', 'chrome', 'webkit', 'browser',
                'wordpress', 'drupal', 'joomla',
                'windows', 'macos', 'android', 'ios'
            ]
            
            if any(indicator in description for indicator in non_kernel_indicators):
                if self.verbose:
                    print(f"CVE {cve_info.cve_id} identified as non-kernel-related based on software indicators")
                return False
        
        # If no clear indicators either way, err on the side of caution
        # and include it (conservative approach)
        if self.verbose:
            print(f"CVE {cve_info.cve_id} classification unclear - including for analysis (conservative approach)")
        
        return True

    def fetch_cve_details(self, cve_id: str) -> Optional[CVEInfo]:
        """Fetch enhanced CVE details from NVD API with thread-safe rate limiting and retry logic.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVEInfo object with enhanced CVE details or None if failed
        """
        for attempt in range(self.API_MAX_RETRIES):
            try:
                # Thread-safe rate limiting using class-level lock
                with VexKernelChecker._api_rate_lock:
                    current_time = time.time()
                    time_since_last_call = current_time - VexKernelChecker._last_global_api_call
                    delay = self.API_RATE_LIMIT_DELAY
                    
                    # Add extra delay for retries (exponential backoff)
                    if attempt > 0:
                        delay *= (self.API_BACKOFF_FACTOR ** attempt)
                        if self.verbose:
                            print(f"Retry {attempt + 1}/{self.API_MAX_RETRIES} for CVE {cve_id} with {delay:.2f}s delay")
                    
                    if time_since_last_call < delay:
                        sleep_time = delay - time_since_last_call
                        if self.verbose:
                            print(f"Rate limiting: sleeping for {sleep_time:.2f}s before API call")
                        time.sleep(sleep_time)
                    
                    VexKernelChecker._last_global_api_call = time.time()
                
                api_url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}'
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
                }
                
                # Only add API key header if we have one
                if self.api_key:
                    headers['apiKey'] = self.api_key
                
                response = requests.get(api_url, headers=headers, timeout=30)
                
                # Handle rate limiting specifically
                if response.status_code == 429:  # Too Many Requests
                    if attempt < self.API_MAX_RETRIES - 1:
                        retry_after = response.headers.get('Retry-After', '60')
                        wait_time = float(retry_after) if retry_after.isdigit() else 60
                        print(f"Rate limited by NVD API for CVE {cve_id}. Waiting {wait_time}s before retry {attempt + 2}")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"Max retries exceeded for CVE {cve_id} due to rate limiting")
                        return None
                
                response.raise_for_status()
                
                cve_data = response.json()
                
                if self.verbose:
                    print(f"Data received from NVD for CVE {cve_id}: {json.dumps(cve_data, indent=2)}")
                
                # Extract enhanced CVE information
                vulnerabilities = cve_data.get('vulnerabilities', [])
                if not vulnerabilities:
                    return None
                    
                cve_details = vulnerabilities[0].get('cve', {})
                
                # Extract CVSS score and severity
                severity = None
                cvss_score = None
                metrics = cve_details.get('metrics', {})
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics and metrics[version]:
                        metric = metrics[version][0]  # Take first metric
                        cvss_data = metric.get('cvssData', {})
                        cvss_score = cvss_data.get('baseScore')
                        severity = cvss_data.get('baseSeverity', metric.get('baseSeverity'))
                        break
                
                # Extract patch URLs
                patch_urls = []
                references = cve_details.get('references', [])
                for reference in references:
                    url = reference.get('url', '')
                    tags = reference.get('tags', [])
                    if 'Patch' in tags and not self._url_ignored(url):
                        patch_urls.append(url)
                
                return CVEInfo(
                    cve_id=cve_id,
                    severity=severity,
                    cvss_score=cvss_score,
                    patch_urls=patch_urls,
                    description=cve_details.get('descriptions', [{}])[0].get('value', ''),
                    published_date=cve_details.get('published', ''),
                    last_modified=cve_details.get('lastModified', '')
                )
                
            except requests.exceptions.RequestException as e:
                if attempt < self.API_MAX_RETRIES - 1:
                    wait_time = self.API_RATE_LIMIT_DELAY * (self.API_BACKOFF_FACTOR ** attempt)
                    print(f"Network error for CVE {cve_id} (attempt {attempt + 1}): {e}. Retrying in {wait_time:.2f}s")
                    time.sleep(wait_time)
                    continue
                else:
                    print(f"Failed to fetch CVE details for {cve_id} after {self.API_MAX_RETRIES} attempts: {e}")
                    return None
            except Exception as e:
                print(f"Unexpected error fetching CVE details for {cve_id}: {e}")
                return None
        
        return None

    def _url_ignored(self, url: str) -> bool:
        """Check if URL should be ignored for patch extraction."""
        return any(url.startswith(ignored_url) for ignored_url in self.IGNORED_URLS)

    def extract_patch_url(self, cve_info: CVEInfo) -> Optional[str]:
        """Extract patch URL from CVE information, prioritizing GitHub sources.
        
        Args:
            cve_info: CVE information object
            
        Returns:
            Best available patch URL (GitHub preferred) or None if not found
        """
        if not cve_info.patch_urls:
            return None
        
        # Prioritize GitHub URLs first
        github_urls = [url for url in cve_info.patch_urls if 'github.com' in url.lower()]
        if github_urls:
            patch_url = github_urls[0]
            if self.verbose:
                print(f"Using prioritized GitHub patch URL: {patch_url}")
            return patch_url
        
        # Fall back to first available patch URL
        patch_url = cve_info.patch_urls[0]
        if self.verbose:
            print(f"Using patch URL: {patch_url}")
        return patch_url

    def get_alternative_patch_urls(self, original_url: str) -> List[str]:
        """Generate alternative patch URLs, prioritizing GitHub sources.
        
        Args:
            original_url: Original patch URL
            
        Returns:
            List of alternative URLs to try, with GitHub URLs prioritized
        """
        alternatives = []
        
        # Extract commit ID from various URL patterns
        commit_id = self._extract_commit_id_from_url(original_url)
        
        if commit_id:
            # GitHub URLs are prioritized first
            github_urls = [
                f"https://github.com/torvalds/linux/commit/{commit_id}.patch",
                f"https://github.com/torvalds/linux/commit/{commit_id}.diff",
                f"https://raw.githubusercontent.com/torvalds/linux/{commit_id}/.patch"
            ]
            alternatives.extend(github_urls)
            
            # Then kernel.org alternatives
            kernel_org_urls = [
                f"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={commit_id}",
                f"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={commit_id}",
                f"https://lore.kernel.org/lkml/{commit_id}/raw"
            ]
            alternatives.extend(kernel_org_urls)
        
        # Try to convert kernel.org URLs to GitHub equivalents
        if 'git.kernel.org' in original_url and commit_id:
            github_alt = f"https://github.com/torvalds/linux/commit/{commit_id}.patch"
            if github_alt not in alternatives:
                alternatives.insert(0, github_alt)  # Prioritize at the beginning
        
        # Try to extract patch URLs from lore.kernel.org patterns
        if 'lore.kernel.org' in original_url:
            # Extract message ID or commit reference for GitHub lookup
            lore_patterns = [
                r'lore\.kernel\.org/[^/]+/([a-f0-9]{12,40})',
                r'msgid=([^&]+)',
            ]
            for pattern in lore_patterns:
                match = re.search(pattern, original_url)
                if match and len(match.group(1)) >= 12:
                    potential_commit = match.group(1)
                    github_alt = f"https://github.com/torvalds/linux/commit/{potential_commit}.patch"
                    if github_alt not in alternatives:
                        alternatives.insert(0, github_alt)
        
        return alternatives

    def _extract_commit_id_from_url(self, url: str) -> Optional[str]:
        """Extract git commit ID from various patch URL formats.
        
        Args:
            url: Patch URL
            
        Returns:
            Commit ID if found, None otherwise
        """
        # Common patterns for commit IDs in URLs
        commit_patterns = [
            r'(?:commit|id)=([a-f0-9]{12,40})',  # ?id=abcd1234 or ?commit=abcd1234
            r'/commit/([a-f0-9]{12,40})',        # /commit/abcd1234
            r'/([a-f0-9]{40})',                  # /abcd1234... (full 40-char hash)
            r'/([a-f0-9]{12,39})',               # /abcd1234... (12-39 char abbreviated hash)
            r'patch-([a-f0-9]{12,40})',          # patch-abcd1234
        ]
        
        for pattern in commit_patterns:
            match = re.search(pattern, url)
            if match:
                commit_id = match.group(1)
                # Validate commit ID format (hex string, reasonable length)
                if len(commit_id) >= 12 and all(c in '0123456789abcdef' for c in commit_id.lower()):
                    return commit_id
        
        return None

    def fetch_patch_with_selenium(self, patch_url: str) -> Optional[str]:
        """Fetch patch content using Selenium WebDriver with enhanced error handling and fallbacks.
        
        Args:
            patch_url: URL to fetch patch from
            
        Returns:
            Patch content or None if failed
        """
        # Try the original URL first
        result = self._fetch_patch_with_selenium_single(patch_url)
        
        # If original failed due to bot detection or other issues, try alternatives
        if result is None:
            alternatives = self.get_alternative_patch_urls(patch_url)
            for alt_url in alternatives:
                if self.verbose:
                    print(f"Trying alternative URL: {alt_url}")
                result = self._fetch_patch_with_selenium_single(alt_url)
                if result is not None:
                    if self.verbose:
                        print(f"✅ Successfully retrieved patch from alternative URL")
                    break
                else:
                    if self.verbose:
                        print(f"Alternative URL also failed")
        
        return result
    
    def _fetch_patch_with_selenium_single(self, patch_url: str) -> Optional[str]:
        """Fetch patch content from a single URL using Selenium WebDriver.
        
        Args:
            patch_url: URL to fetch patch from
            
        Returns:
            Patch content or None if failed
        """
        driver = None
        try:
            if self.verbose:
                print(f"Initializing WebDriver for URL: {patch_url}")
            
            # Validate WebDriver path before attempting to use it
            if not self.edge_driver_path:
                raise ValueError("Edge WebDriver path is not set")
            
            if not os.path.isfile(self.edge_driver_path):
                raise FileNotFoundError(f"Edge WebDriver not found at: {self.edge_driver_path}")
            
            service = Service(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            
            # Enhanced WebDriver options for better reliability and stealth
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_argument('--disable-extensions')
            options.add_argument('--disable-plugins')
            options.add_argument('--disable-images')
            options.add_argument('--disable-javascript')  # Many patches don't need JS
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-features=VizDisplayCompositor')
            options.add_argument('--window-size=1920,1080')
            
            # Use a more realistic user agent to avoid bot detection
            options.add_argument('--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            
            # Additional stealth options
            options.add_experimental_option("excludeSwitches", ["enable-automation"])
            options.add_experimental_option('useAutomationExtension', False)
            
            # Set timeouts
            options.add_argument('--page-load-strategy=eager')
            
            if self.verbose:
                print("Starting Edge WebDriver...")
            
            try:
                driver = webdriver.Edge(service=service, options=options)
            except SessionNotCreatedException as e:
                print(f"Failed to create WebDriver session: {e}")
                print("Possible causes:")
                print("  - Edge WebDriver version incompatible with installed Edge browser")
                print("  - Edge browser not installed")
                print("  - WebDriver permissions issue")
                return None
            except WebDriverException as e:
                print(f"WebDriver initialization failed: {e}")
                return None
            
            # Set timeouts
            driver.set_page_load_timeout(30)
            driver.implicitly_wait(10)
            
            if self.verbose:
                print(f"Navigating to: {patch_url}")
            
            try:
                driver.get(patch_url)
                # Wait a moment for any dynamic content/redirects to settle
                time.sleep(2)
            except TimeoutException:
                if self.verbose:
                    print(f"Timeout while loading page: {patch_url}")
                    print("The page took too long to load (>30 seconds)")
                return None
            except WebDriverException as e:
                if self.verbose:
                    print(f"Failed to navigate to URL {patch_url}: {e}")
                return None
            
            # Check for common error pages and bot detection
            page_title = driver.title.lower()
            page_source_snippet = driver.page_source[:1000].lower()
            
            # Check for bot detection pages
            bot_detection_indicators = [
                "making sure you're not a bot", "just a moment", "cloudflare", 
                "security check", "checking your browser", "please wait",
                "anti-bot", "ddos protection", "rate limiting"
            ]
            
            if any(indicator in page_title or indicator in page_source_snippet 
                   for indicator in bot_detection_indicators):
                if self.verbose:
                    print(f"⚠️  Bot detection page detected. Page title: '{driver.title}'")
                    print("This indicates that the website is blocking automated access.")
                    print("Consider using alternative patch sources or manual verification.")
                return None
            
            # Check for other common error pages
            if any(error_indicator in page_title for error_indicator in [
                "oh noes!", "404", "not found", "error", "access denied", "forbidden"
            ]):
                if self.verbose:
                    print(f"Error page detected. Page title: '{driver.title}'")
                return None
            
            # Check if page loaded successfully
            if not page_title or "loading" in page_title:
                if self.verbose:
                    print("Page appears to still be loading or failed to load content")
                return None
            
            if self.verbose:
                print(f"Page loaded successfully. Title: '{driver.title}'")
                print("Searching for patch content...")
            
            # Try multiple strategies to find patch content
            patch_content = None
            
            # Strategy 1: Look for <pre> tag (most common for patches)
            try:
                patch_element = WebDriverWait(driver, 15).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'pre'))
                )
                patch_content = patch_element.text
                if self.verbose:
                    print("Found patch content in <pre> tag")
            except TimeoutException:
                if self.verbose:
                    print("No <pre> tag found, trying alternative methods...")
            
            # Strategy 2: Look for code blocks
            if not patch_content:
                try:
                    code_elements = driver.find_elements(By.TAG_NAME, 'code')
                    if code_elements:
                        patch_content = '\n'.join([elem.text for elem in code_elements if elem.text.strip()])
                        if self.verbose:
                            print("Found patch content in <code> tags")
                except NoSuchElementException:
                    pass
            
            # Strategy 3: Look for elements with specific classes or IDs commonly used for patches
            if not patch_content:
                selectors_to_try = [
                    '.diff', '.patch', '#patch', '.code', '.highlight',
                    '[class*="diff"]', '[class*="patch"]', '[id*="diff"]'
                ]
                
                for selector in selectors_to_try:
                    try:
                        elements = driver.find_elements(By.CSS_SELECTOR, selector)
                        if elements:
                            patch_content = '\n'.join([elem.text for elem in elements if elem.text.strip()])
                            if patch_content:
                                if self.verbose:
                                    print(f"Found patch content using selector: {selector}")
                                break
                    except Exception:
                        continue
            
            # Strategy 4: Last resort - get page source and try to extract patch content
            if not patch_content:
                if self.verbose:
                    print("Attempting to extract patch from page source...")
                page_source = driver.page_source
                
                # Look for common patch patterns in source
                import re
                patch_patterns = [
                    r'<pre[^>]*>(.*?)</pre>',
                    r'<code[^>]*>(.*?)</code>',
                    r'diff --git.*?(?=<|$)',
                ]
                
                for pattern in patch_patterns:
                    matches = re.findall(pattern, page_source, re.DOTALL | re.IGNORECASE)
                    if matches:
                        patch_content = '\n'.join(matches)
                        # Remove HTML tags
                        patch_content = re.sub(r'<[^>]+>', '', patch_content)
                        if patch_content.strip():
                            if self.verbose:
                                print("Extracted patch content from page source")
                            break
            
            if not patch_content or not patch_content.strip():
                if self.verbose:
                    print(f"No patch content found on page: {patch_url}")
                    print("The page may not contain patch information or uses an unsupported format")
                return None
            
            if self.verbose:
                print(f"Successfully extracted patch content ({len(patch_content)} characters)")
            
            return patch_content
            
        except FileNotFoundError as e:
            print(f"File system error: {e}")
            return None
        except PermissionError as e:
            print(f"Permission error accessing WebDriver: {e}")
            print("Try running with appropriate permissions or check file ownership")
            return None
        except Exception as e:
            print(f"Unexpected error in WebDriver operation: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return None
        finally:
            if driver:
                try:
                    if self.verbose:
                        print("Closing WebDriver...")
                    driver.quit()
                except Exception as e:
                    if self.verbose:
                        print(f"Warning: Error while closing WebDriver: {e}")
                    # Don't re-raise, as this is cleanup

    def fetch_patch_content_with_github_priority(self, patch_url: str) -> Optional[str]:
        """Fetch patch content with GitHub prioritized as the first source.
        
        This method implements the new GitHub-first strategy:
        1. Try GitHub directly if available
        2. Extract commit ID and try GitHub alternatives
        3. Fall back to original URL with Selenium
        4. Try other alternative sources
        
        Args:
            patch_url: Original patch URL
            
        Returns:
            Patch content or None if all methods fail
        """
        if self.verbose:
            print(f"Fetching patch content for: {patch_url}")
        
        # Step 1: If it's already a GitHub URL, try it directly first
        if 'github.com' in patch_url:
            if self.verbose:
                print("Trying GitHub URL directly (no WebDriver needed)")
            
            try:
                response = requests.get(patch_url, timeout=30)
                response.raise_for_status()
                if self.verbose:
                    print("✅ Successfully fetched patch from GitHub (direct)")
                return response.text
            except requests.RequestException as e:
                if self.verbose:
                    print(f"Direct GitHub request failed: {e}")
        
        # Step 2: Extract commit ID and try GitHub alternatives first
        commit_id = self._extract_commit_id_from_url(patch_url)
        if commit_id:
            if self.verbose:
                print(f"Extracted commit ID: {commit_id}, trying GitHub alternatives")
            
            # Try multiple GitHub URL formats
            github_urls = [
                f"https://github.com/torvalds/linux/commit/{commit_id}.patch",
                f"https://github.com/torvalds/linux/commit/{commit_id}.diff"
            ]
            
            for github_url in github_urls:
                try:
                    if self.verbose:
                        print(f"Trying GitHub URL: {github_url}")
                    response = requests.get(github_url, timeout=30)
                    response.raise_for_status()
                    if self.verbose:
                        print("✅ Successfully fetched patch from GitHub alternative")
                    return response.text
                except requests.RequestException as e:
                    if self.verbose:
                        print(f"GitHub alternative failed: {e}")
                    continue
        
        # Step 3: Fall back to original URL with Selenium (for sites requiring JavaScript)
        if self.verbose:
            print("GitHub alternatives failed, trying original URL with WebDriver")
        
        patch_content = self.fetch_patch_with_selenium(patch_url)
        if patch_content:
            if self.verbose:
                print("✅ Successfully fetched patch using WebDriver")
            return patch_content
        
        # Step 4: Try other alternative sources as last resort
        if self.verbose:
            print("WebDriver also failed, trying remaining alternatives")
        
        alternatives = self.get_alternative_patch_urls(patch_url)
        # Skip GitHub URLs since we already tried them above
        non_github_alternatives = [url for url in alternatives if 'github.com' not in url]
        
        for alt_url in non_github_alternatives:
            if self.verbose:
                print(f"Trying alternative URL: {alt_url}")
            
            # Try direct request first for kernel.org, lore.kernel.org, etc.
            try:
                response = requests.get(alt_url, timeout=30)
                response.raise_for_status()
                if self.verbose:
                    print(f"✅ Successfully fetched patch from alternative: {alt_url}")
                return response.text
            except requests.RequestException:
                # If direct request fails, try with WebDriver
                alt_content = self._fetch_patch_with_selenium_single(alt_url)
                if alt_content:
                    if self.verbose:
                        print(f"✅ Successfully fetched patch from alternative with WebDriver: {alt_url}")
                    return alt_content
        
        if self.verbose:
            print("❌ All patch fetching methods failed")
        return None

    @staticmethod
    def fetch_patch_from_github(commit_id: str) -> Optional[str]:
        """Fetch patch from GitHub using commit ID.
        
        Args:
            commit_id: Git commit ID
            
        Returns:
            Patch content or None if failed
        """
        try:
            github_url = f"https://github.com/torvalds/linux/commit/{commit_id}.patch"
            response = requests.get(github_url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"Failed to fetch patch information from GitHub: {e}")
            return None

    def extract_sourcefiles(self, patch_info: str) -> Set[str]:
        """Extract source files from patch information with optimized pattern matching.
        
        Args:
            patch_info: Patch content as string
            
        Returns:
            Set of source file paths
        """
        sourcefiles = set()
        
        # Use precompiled pattern for better performance
        diff_pattern = self._patch_patterns[0]  # diff --git pattern
        
        for match in diff_pattern.finditer(patch_info):
            source_file = match.group(1)
            sourcefiles.add(source_file)
            if self.verbose:
                print(f"Found source file: {source_file}")
        
        return sourcefiles

    def extract_config_options_from_makefile(self, makefile_path: str, source_file_name: str) -> Set[str]:
        """Extract configuration options from Makefile for a given source file.
        
        This enhanced version handles:
        - Standard obj-$(CONFIG_*) patterns
        - Multi-line assignments with backslash continuation
        - Variable references and expansions
        - Different object file patterns (obj-y, obj-m, obj-n)
        - Composite object files
        - Subdirectory inclusions
        - Include statements and recursive file processing
        - Performance optimizations with caching
        
        Args:
            makefile_path: Path to Makefile
            source_file_name: Name of source file to find config for
            
        Returns:
            Set of configuration options
        """
        # Check cache first
        cache_key = f"{makefile_path}:{source_file_name}"
        if cache_key in self._config_cache:
            return self._config_cache[cache_key]
        
        config_options = set()
        processed_files = set()  # Prevent infinite recursion
        
        result = self._extract_config_recursive_optimized(makefile_path, source_file_name, processed_files)
        
        # Cache the result
        self._config_cache[cache_key] = result
        
        # Limit cache size to prevent memory issues
        if len(self._config_cache) > self.CONFIG_CACHE_SIZE:
            # Remove oldest entries (simple FIFO for now)
            oldest_keys = list(self._config_cache.keys())[:50]
            for key in oldest_keys:
                del self._config_cache[key]
        
        return result

    def _extract_config_recursive_optimized(self, makefile_path: str, source_file_name: str, processed_files: Set[str]) -> Set[str]:
        """Ultra-optimized recursive extraction of configuration options from Makefile and included files.
        
        Args:
            makefile_path: Path to Makefile
            source_file_name: Name of source file to find config for
            processed_files: Set of already processed files to prevent recursion
            
        Returns:
            Set of configuration options
        """
        config_options = set()
        
        # Prevent infinite recursion with depth and count limits
        abs_makefile_path = os.path.abspath(makefile_path)
        if (abs_makefile_path in processed_files or 
            len(processed_files) > self.MAX_KCONFIG_RECURSION_DEPTH):
            return config_options
        processed_files.add(abs_makefile_path)
        
        # Use cached file content
        content = self._get_cached_file_content(makefile_path)
        if not content:
            return config_options
        
        # Use cached Makefile variables
        makefile_vars = self._get_cached_makefile_vars(makefile_path)
        
        # Ultra-fast config extraction
        config_options.update(self._extract_configs_ultra_fast(content, source_file_name, makefile_vars))
        
        # Process includes with strict limits for performance
        if len(processed_files) < self.MAX_KCONFIG_RECURSION_DEPTH // 2:
            include_pattern = re.compile(r'^-?include\s+(.+)$', re.MULTILINE)
            include_matches = include_pattern.findall(content)
            
            for include_match in include_matches[:self.MAX_INCLUDE_FILES_PER_MAKEFILE]:
                include_pattern_str = include_match.strip()
                included_files = self._resolve_include_pattern(include_pattern_str, makefile_path, makefile_vars)
                
                for included_file in included_files[:3]:  # Limit to 3 includes per pattern
                    if os.path.exists(included_file) and included_file not in processed_files:
                        if self.verbose:
                            print(f"Processing included file: {included_file}")
                        included_configs = self._extract_config_recursive_optimized(
                            included_file, source_file_name, processed_files
                        )
                        config_options.update(included_configs)
        
        return config_options

    def _resolve_include_pattern(self, include_pattern: str, makefile_path: str, makefile_vars: dict) -> List[str]:
        """Resolve include patterns to actual file paths.
        
        Args:
            include_pattern: Include pattern from Makefile
            makefile_path: Path to current Makefile
            makefile_vars: Dictionary of Makefile variables
            
        Returns:
            List of resolved file paths
        """
        include_files = []
        
        try:
            # Expand variables in the include pattern
            expanded_pattern = self._expand_makefile_variables(include_pattern, makefile_vars)
            
            # Handle relative paths
            if not os.path.isabs(expanded_pattern):
                base_dir = os.path.dirname(makefile_path)
                expanded_pattern = os.path.join(base_dir, expanded_pattern)
            
            # Handle wildcards
            if '*' in expanded_pattern or '?' in expanded_pattern:
                import glob
                matching_files = glob.glob(expanded_pattern)
                include_files.extend(matching_files)
            else:
                include_files.append(expanded_pattern)
                
        except Exception as e:
            if self.verbose:
                print(f"Error resolving include pattern '{include_pattern}': {e}")
        
        return include_files

    def _extract_configs_from_line(self, line: str, source_file_name: str, makefile_path: str, makefile_vars: dict) -> Set[str]:
        """Extract configuration options from a single Makefile line.
        
        Args:
            line: Line from Makefile
            source_file_name: Name of source file to find config for
            makefile_path: Path to Makefile (for directory-based matching)
            makefile_vars: Dictionary of Makefile variables for expansion
            
        Returns:
            Set of configuration options found in this line
        """
        config_options = set()
        base_name = os.path.splitext(source_file_name)[0]
        dir_name = os.path.basename(os.path.dirname(makefile_path))
        
        # Expand variables once
        expanded_line = self._expand_makefile_variables(line, makefile_vars)
        
        # Quick check: if line doesn't contain CONFIG_, skip expensive processing
        if 'CONFIG_' not in expanded_line:
            return config_options
        
        # Quick check: if line doesn't contain source file references, skip most patterns
        has_source_ref = (base_name in expanded_line or 
                         source_file_name in expanded_line or 
                         dir_name in expanded_line)
        
        if not has_source_ref and not any(keyword in expanded_line.lower() for keyword in ['ifdef', 'ifeq', 'ifneq']):
            # Only extract standalone CONFIG references
            config_matches = re.findall(r'CONFIG_[A-Z0-9_]+', expanded_line)
            return set(config_matches)
        
        # Use precompiled patterns for better performance
        target_files = [base_name, source_file_name, dir_name]
        
        for target in target_files:
            if target in expanded_line:
                # Apply efficient pattern matching
                for pattern_template in [
                    r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?=\s*.*\b{}\b',
                    r'{}-\$\((CONFIG_[A-Z0-9_]+)\)',
                    r'{}-objs-\$\((CONFIG_[A-Z0-9_]+)\)',
                ]:
                    pattern = pattern_template.format(re.escape(target))
                    matches = re.finditer(pattern, expanded_line, re.IGNORECASE)
                    for match in matches:
                        for group_idx in range(1, match.lastindex + 1 if match.lastindex else 1):
                            group_val = match.group(group_idx)
                            if group_val and group_val.startswith('CONFIG_'):
                                config_options.add(group_val)
        
        # Quick conditional pattern matching
        if any(keyword in expanded_line for keyword in ['ifdef', 'ifeq', 'ifneq']):
            conditional_configs = re.findall(r'CONFIG_[A-Z0-9_]+', expanded_line)
            if has_source_ref:
                config_options.update(conditional_configs)
        
        return config_options

    def _expand_makefile_variables(self, line: str, makefile_vars: dict) -> str:
        """Expand Makefile variables in a line.
        
        Args:
            line: Line containing potential variable references
            makefile_vars: Dictionary of variable definitions
            
        Returns:
            Line with variables expanded
        """
        # Simple variable expansion for $(VAR) and ${VAR} patterns
        def replace_var(match):
            var_name = match.group(1)
            return makefile_vars.get(var_name, match.group(0))
        
        # Expand $(VAR) style variables
        expanded = re.sub(r'\$\(([A-Z_][A-Z0-9_]*)\)', replace_var, line)
        # Expand ${VAR} style variables  
        expanded = re.sub(r'\$\{([A-Z_][A-Z0-9_]*)\}', replace_var, expanded)
        
        return expanded

    def _find_kconfig_dependencies(self, config_option: str, kernel_source_path: str) -> Set[str]:
        """Find additional config dependencies from Kconfig files.
        
        This method looks for 'depends on' relationships in Kconfig files
        to find transitive dependencies.
        
        Args:
            config_option: Configuration option to find dependencies for
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of additional configuration options this depends on
        """
        dependencies = set()
        
        try:
            # Look for Kconfig files in the kernel source
            for root, dirs, files in os.walk(kernel_source_path):
                for file in files:
                    if file in ['Kconfig', 'Kconfig.debug', 'Kconfig.platform'] or file.startswith('Kconfig.'):
                        kconfig_path = os.path.join(root, file)
                        dependencies.update(self._parse_kconfig_file(kconfig_path, config_option))
                        
        except Exception as e:
            if self.verbose:
                print(f"Error searching Kconfig files: {e}")
        
        return dependencies

    def _parse_kconfig_file(self, kconfig_path: str, target_config: str) -> Set[str]:
        """Parse a single Kconfig file for dependencies.
        
        Args:
            kconfig_path: Path to Kconfig file
            target_config: Configuration option to find dependencies for
            
        Returns:
            Set of configuration options this depends on
        """
        dependencies = set()
        
        try:
            with open(kconfig_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read()
            
            # Look for the target config definition
            config_pattern = rf'config\s+{target_config.replace("CONFIG_", "")}\s*\n(.*?)(?=config\s+|\Z)'
            match = re.search(config_pattern, content, re.DOTALL | re.IGNORECASE)
            
            if match:
                config_block = match.group(1)
                
                # Find 'depends on' lines
                depends_matches = re.finditer(r'depends\s+on\s+(.+)', config_block, re.IGNORECASE)
                for depends_match in depends_matches:
                    depends_line = depends_match.group(1).strip()
                    
                    # Extract config options from the depends line
                    config_refs = re.findall(r'\b[A-Z_][A-Z0-9_]*\b', depends_line)
                    for config_ref in config_refs:
                        if config_ref not in ['AND', 'OR', 'NOT', 'IF']:
                            dependencies.add(f'CONFIG_{config_ref}')
                
                if self.verbose and dependencies:
                    print(f"Found Kconfig dependencies for {target_config}: {', '.join(dependencies)}")
                    
        except Exception as e:
            if self.verbose:
                print(f"Error parsing Kconfig file {kconfig_path}: {e}")
        
        return dependencies

    def find_makefile_config_options(self, source_file_path: str, makefile_path: str, kernel_source_path: str) -> Set[str]:
        """Find configuration options for a source file by analyzing Makefile.
        
        This enhanced version also looks for Kconfig dependencies to provide
        a more complete picture of configuration requirements.
        
        Args:
            source_file_path: Path to source file
            makefile_path: Path to Makefile
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of configuration options
        """
        if self.verbose:
            print(f"Analyzing Makefile {makefile_path} for {source_file_path}")
        
        # Primary analysis: direct Makefile parsing
        config_options = self.extract_config_options_from_makefile(makefile_path, os.path.basename(source_file_path))
        if config_options:
            if self.verbose:
                print(f"Found direct config options: {', '.join(config_options)}")
        else:
            # Try with parent directory context
            parent_dir = os.path.dirname(source_file_path)
            config_options = self.extract_config_options_from_makefile(
                makefile_path, f"{os.path.basename(parent_dir)}/{os.path.basename(source_file_path)}"
            )
            
            if not config_options:
                # Check parent directories for matches
                while parent_dir != "" and parent_dir != kernel_source_path:
                    config_options = self.extract_config_options_from_makefile(makefile_path, os.path.basename(parent_dir))
                    if config_options:
                        if self.verbose:
                            print(f"Found config options via parent directory {os.path.basename(parent_dir)}: {', '.join(config_options)}")
                        break
                    parent_dir = os.path.dirname(parent_dir)
        
        # Secondary analysis: find Kconfig dependencies
        all_config_options = set(config_options)
        for config_option in config_options:
            try:
                dependencies = self._find_kconfig_dependencies(config_option, kernel_source_path)
                all_config_options.update(dependencies)
                if dependencies and self.verbose:
                    print(f"Found Kconfig dependencies for {config_option}: {', '.join(dependencies)}")
            except Exception as e:
                if self.verbose:
                    print(f"Error finding Kconfig dependencies for {config_option}: {e}")
        
        return all_config_options

    def find_makefiles_config_options(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Ultra-fast configuration options discovery using smart search ordering.
        
        This optimized version uses:
        - Priority-based directory searching
        - Aggressive caching at multiple levels
        - Fast makefile discovery
        - Optimized pattern matching
        
        Args:
            source_file_path: Path to source file
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of configuration options
        """
        if self.verbose:
            print(f"Ultra-fast config search for: {source_file_path}")
        
        all_config_options = set()
        
        # Use fast makefile discovery
        makefiles = self._find_makefiles_fast(kernel_source_path, source_file_path)
        
        if self.verbose:
            print(f"Found {len(makefiles)} makefiles to analyze")
        
        # Analyze each makefile with fast extraction
        for makefile_path in makefiles:
            if self.verbose:
                print(f"Analyzing {makefile_path}")
            
            config_options = self.find_makefile_config_options(source_file_path, makefile_path, kernel_source_path)
            if config_options:
                all_config_options.update(config_options)
                if self.verbose:
                    print(f"Found config options in {makefile_path}: {', '.join(config_options)}")
        
        # If no options found in Makefiles, try source file analysis
        if not all_config_options:
            if self.verbose:
                print("No Makefile configs found, analyzing source file directly")
            source_configs = self._analyze_source_file_ultra_fast(source_file_path)
            all_config_options.update(source_configs)
        
        # If still no options, try path-based inference
        if not all_config_options:
            if self.verbose:
                print("No direct configs found, trying path-based inference")
            path_configs = self._infer_config_from_path(source_file_path, kernel_source_path)
            all_config_options.update(path_configs)
        
        return all_config_options

    def _analyze_related_makefiles(self, search_dir: str, source_file_path: str, kernel_source_path: str, config_options: Set[str]):
        """Analyze related Makefiles that might contain relevant configuration.
        
        Args:
            search_dir: Directory to search in
            source_file_path: Path to source file
            kernel_source_path: Root path of kernel sources
            config_options: Set to add found config options to
        """
        source_basename = os.path.splitext(os.path.basename(source_file_path))[0]
        
        # Look for makefiles with names related to the source file or directory
        related_patterns = [
            f"Makefile.{source_basename}",
            f"{source_basename}.mk",
            f"Makefile.{os.path.basename(search_dir)}",
            f"{os.path.basename(search_dir)}.mk"
        ]
        
        for pattern in related_patterns:
            related_makefile = os.path.join(search_dir, pattern)
            if os.path.exists(related_makefile):
                if self.verbose:
                    print(f"Analyzing related makefile: {related_makefile}")
                found_options = self.find_makefile_config_options(source_file_path, related_makefile, kernel_source_path)
                config_options.update(found_options)

    def _advanced_config_search(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Perform advanced configuration option search using various heuristics.
        
        Args:
            source_file_path: Path to source file
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of configuration options found through advanced methods
        """
        config_options = set()
        
        try:
            # Strategy 1: Search for the source filename in all Makefiles
            if self.verbose:
                print("Performing advanced search: scanning all Makefiles for source file references")
            
            config_options.update(self._search_all_makefiles(source_file_path, kernel_source_path))
            
            # Strategy 2: Analyze source file content for config hints
            if self.verbose:
                print("Performing advanced search: analyzing source file for config hints")
            
            config_options.update(self._analyze_source_file_config_hints(source_file_path))
            
            # Strategy 3: Use directory naming conventions
            if self.verbose:
                print("Performing advanced search: using directory naming conventions")
            
            config_options.update(self._infer_config_from_path(source_file_path, kernel_source_path))
            
        except Exception as e:
            if self.verbose:
                print(f"Error in advanced config search: {e}")
        
        return config_options

    def _search_all_makefiles(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Ultra-optimized search of all Makefiles in kernel source for references to the source file.
        
        Args:
            source_file_path: Path to source file
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of configuration options found
        """
        config_options = set()
        source_basename = os.path.basename(source_file_path)
        source_name = os.path.splitext(source_basename)[0]
        
        # Use Path for better performance
        kernel_path = Path(kernel_source_path)
        
        # Highly optimized search with smart prioritization
        files_searched = 0
        
        try:
            # Build priority-ordered search candidates
            search_candidates = []
            
            # Priority 1: Directories related to source file path
            source_dir_parts = Path(source_file_path).parts
            for i, part in enumerate(source_dir_parts):
                if part in ['drivers', 'fs', 'net', 'sound', 'crypto', 'security']:
                    potential_dirs = list(kernel_path.glob(f"**/{part}/**/Makefile"))[:20]
                    for makefile_path in potential_dirs:
                        priority = 1000 - i * 100  # Higher priority for closer matches
                        search_candidates.append((makefile_path, priority))
            
            # Priority 2: Source and parent directories
            source_dir = os.path.dirname(source_file_path)
            for potential_makefile in ['Makefile', 'Kbuild']:
                makefile_path = Path(source_dir) / potential_makefile
                if makefile_path.exists():
                    search_candidates.append((makefile_path, 2000))
            
            # Priority 3: Common kernel subsystem makefiles
            priority_patterns = [
                ('drivers/*/Makefile', 800),
                ('fs/*/Makefile', 700),
                ('net/*/Makefile', 600),
                ('sound/*/Makefile', 500),
                ('crypto/Makefile', 400),
                ('security/*/Makefile', 400),
            ]
            
            for pattern, priority in priority_patterns:
                makefiles = list(kernel_path.glob(pattern))[:10]  # Limit per pattern
                for makefile_path in makefiles:
                    search_candidates.append((makefile_path, priority))
            
            # Sort by priority (highest first) and limit total candidates
            search_candidates.sort(key=lambda x: x[1], reverse=True)
            search_candidates = search_candidates[:self.MAX_MAKEFILE_SEARCH_FILES]
            
            # Process in priority order
            for makefile_path, priority in search_candidates:
                if files_searched >= self.MAX_MAKEFILE_SEARCH_FILES:
                    break
                
                try:
                    # Use cached content for ultra-fast processing
                    content = self._get_cached_file_content(str(makefile_path))
                    if content and (source_basename in content or source_name in content):
                        found_options = self.extract_config_options_from_makefile(str(makefile_path), source_basename)
                        config_options.update(found_options)
                        if found_options and self.verbose:
                            print(f"Priority search found configs in {makefile_path}: {', '.join(found_options)}")
                except Exception:
                    pass  # Skip files that can't be read
                
                files_searched += 1
            
            if self.verbose and files_searched >= self.MAX_MAKEFILE_SEARCH_FILES:
                print(f"Limited priority Makefile search to {files_searched} files for optimal performance")
                    
        except Exception as e:
            if self.verbose:
                print(f"Error in global Makefile search: {e}")
        
        return config_options

    def _analyze_source_file_config_hints(self, source_file_path: str) -> Set[str]:
        """Analyze source file content for configuration hints with caching.
        
        Look for #ifdef CONFIG_* patterns and other hints in the source code.
        
        Args:
            source_file_path: Path to source file
            
        Returns:
            Set of configuration options found
        """
        # Check cache first
        if source_file_path in self._path_cache:
            return self._path_cache[source_file_path]
        
        config_options = set()
        
        try:
            # Use cached file content
            content = self._get_cached_file_content(source_file_path)
            if not content:
                self._path_cache[source_file_path] = config_options
                return config_options
            
            # Use precompiled patterns for better performance
            ifdef_pattern = self._patch_patterns[1]  # #ifdef pattern
            if_defined_pattern = self._patch_patterns[2]  # #if defined pattern  
            is_enabled_pattern = self._patch_patterns[3]  # IS_ENABLED pattern
            
            # Find all matches efficiently
            for pattern in [ifdef_pattern, if_defined_pattern, is_enabled_pattern]:
                for match in pattern.finditer(content):
                    config_options.add(match.group(1))
            
            if config_options and self.verbose:
                print(f"Found config hints in source file {source_file_path}: {', '.join(config_options)}")
        
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing source file {source_file_path}: {e}")
        
        # Cache the result
        self._path_cache[source_file_path] = config_options
        
        # Limit cache size
        if len(self._path_cache) > 200:
            # Remove oldest entries
            oldest_keys = list(self._path_cache.keys())[:50]
            for key in oldest_keys:
                del self._path_cache[key]
        
        return config_options

    def _infer_config_from_path(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Infer configuration options from file path using common kernel conventions.
        
        Args:
            source_file_path: Path to source file
            kernel_source_path: Root path of kernel sources
            
        Returns:
            Set of configuration options inferred from path
        """
        config_options = set()
        
        try:
            # Get relative path within kernel source
            rel_path = os.path.relpath(source_file_path, kernel_source_path)
            path_parts = rel_path.split(os.sep)
            
            # Common kernel subsystem to config mappings
            subsystem_configs = {
                'drivers/net': ['CONFIG_NET', 'CONFIG_NETDEVICES'],
                'drivers/usb': ['CONFIG_USB'],
                'drivers/pci': ['CONFIG_PCI'],
                'drivers/block': ['CONFIG_BLOCK'],
                'drivers/scsi': ['CONFIG_SCSI'],
                'drivers/char': ['CONFIG_CHAR_DEVICES'],
                'fs': ['CONFIG_FILESYSTEMS'],
                'net': ['CONFIG_NET'],
                'sound': ['CONFIG_SOUND'],
                'crypto': ['CONFIG_CRYPTO'],
                'security': ['CONFIG_SECURITY'],
                'mm': ['CONFIG_MM'],
                'kernel': ['CONFIG_KERNEL'],
            }
            
            # Check for subsystem matches
            for subsystem, configs in subsystem_configs.items():
                if subsystem in rel_path:
                    config_options.update(configs)
                    if self.verbose:
                        print(f"Inferred config options from path subsystem {subsystem}: {', '.join(configs)}")
            
            # Try to infer from directory names
            for part in path_parts:
                if part.startswith('drivers'):
                    continue  # Skip the generic 'drivers' part
                
                # Convert directory names to potential config names
                potential_config = f"CONFIG_{part.upper().replace('-', '_')}"
                if re.match(r'^CONFIG_[A-Z0-9_]+$', potential_config):
                    config_options.add(potential_config)
                    if self.verbose:
                        print(f"Inferred config option from directory name: {potential_config}")
                        
        except Exception as e:
            if self.verbose:
                print(f"Error inferring config from path: {e}")
        
        return config_options

    def in_kernel_config(self, config_options: Set[str], kernel_config: List[str]) -> VulnerabilityAnalysis:
        """Check if configuration options are enabled in kernel config and return analysis.
        
        Args:
            config_options: Set of configuration options to check
            kernel_config: List of enabled kernel configuration options
            
        Returns:
            VulnerabilityAnalysis object with the result
        """
        if config_options <= self.ENABLED_DEFAULT_OPTIONS:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.AFFECTED,
                detail=f"Uses default enabled options: {', '.join(config_options)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        if config_options == set():
            return VulnerabilityAnalysis(
                state=VulnerabilityState.AFFECTED,
                detail="No specific configuration options found - assuming vulnerable",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        missing_options = config_options - set(kernel_config)
        if missing_options:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.REQUIRES_CONFIGURATION,
                detail=f"Required configuration options not enabled: {', '.join(missing_options)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        return VulnerabilityAnalysis(
            state=VulnerabilityState.AFFECTED,
            detail=f"All required configuration options are enabled: {', '.join(config_options)}",
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )

    @staticmethod
    def extract_arch_info(path: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract architecture information from file path.
        
        Args:
            path: File path to analyze
            
        Returns:
            Tuple of (architecture_name, architecture_config)
        """
        match = re.search(r'arch/([^/]+)/', path)
        if match:
            arch_name = match.group(1)
            arch_config = f"CONFIG_ARCH_{arch_name.upper()}"
            return arch_name, arch_config
        return None, None

    @timed_method
    def check_kernel_config(self, cve: Dict, kernel_config: List[str], kernel_source_path: str) -> VulnerabilityAnalysis:
        """Check if a CVE affects the current kernel configuration.
        
        Args:
            cve: CVE vulnerability data
            kernel_config: List of enabled kernel configuration options
            kernel_source_path: Path to kernel source directory
            
        Returns:
            VulnerabilityAnalysis object with the assessment result
        """
        cve_id = cve.get('id', 'Unknown')
        
        # Check if already processed
        if cve_id in self._processed_cves:
            if self.verbose:
                print(f"CVE {cve_id} already processed, skipping")
            return None
        
        self._processed_cves.add(cve_id)
        
        cve_info = self.fetch_cve_details(cve_id)
        if not cve_info:
            # Skip CVE if we can't fetch details - don't mark as under_investigation
            if self.verbose:
                print(f"Skipping CVE {cve_id}: Could not fetch CVE details from NVD")
            return None
        
        # Check if this CVE is kernel-related - skip if not (unless analyzing all CVEs)
        if not self.analyze_all_cves and not self.is_kernel_related_cve(cve_info):
            if self.verbose:
                print(f"Skipping CVE {cve_id}: Not kernel-related (use --analyze-all-cves to include)")
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.COMPONENT_NOT_PRESENT,
                detail=f"CVE is not related to the Linux kernel - skipped from kernel analysis.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        # Only attempt patch checking if it's enabled
        if not self.check_patches:
            # Perform config-only analysis when patch checking is disabled
            if self.verbose:
                print(f"Performing config-only analysis for CVE {cve_id} (patch checking disabled)")
            
            return VulnerabilityAnalysis(
                state=VulnerabilityState.UNDER_INVESTIGATION,
                justification=Justification.REQUIRES_CONFIGURATION,
                detail=f"Config-only analysis - patch checking disabled. Manual review recommended to determine if CVE affects this kernel configuration.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        # Attempt patch-based analysis when enabled
        patch_url = self.extract_patch_url(cve_info)
        if not patch_url:
            # Fall back to config-only analysis if no patch URL found
            if self.verbose:
                print(f"No patch URL found for CVE {cve_id}, falling back to config-only analysis")
            
            return VulnerabilityAnalysis(
                state=VulnerabilityState.UNDER_INVESTIGATION,
                justification=Justification.REQUIRES_CONFIGURATION,
                detail=f"No patch URL available in CVE references. Manual review recommended to determine impact.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        patch_info = self.fetch_patch_content_with_github_priority(patch_url)
        
        if not patch_info:
            # Fall back to config-only analysis if patch content cannot be fetched
            if self.verbose:
                print(f"Could not fetch patch content for CVE {cve_id}, falling back to config-only analysis")
            
            return VulnerabilityAnalysis(
                state=VulnerabilityState.UNDER_INVESTIGATION,
                justification=Justification.REQUIRES_CONFIGURATION,
                detail=f"Could not fetch patch content from {patch_url}. Manual review recommended.",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        sourcefiles = self.extract_sourcefiles(patch_info)
        if not sourcefiles:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.VULNERABLE_CODE_NOT_PRESENT,
                detail="No C source files found in patch",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        if self.verbose:
            print(f"Source files found in the patch: {sourcefiles}")
        
        all_config_options = set()
        architecture_issues = []
        
        for sourcefile in sourcefiles:
            source_file_path = self._replace_multiple_substrings(sourcefile, self.PATH_REPLACEMENTS)
            arch, arch_config = self.extract_arch_info(source_file_path)
            
            if arch and not arch.startswith("arm"):
                architecture_issues.append(arch_config)
                continue
            
            source_file_path = os.path.join(kernel_source_path, source_file_path)
            if self.verbose:
                print(f"Analyzing source path: {source_file_path}")
            
            config_options = self.find_makefiles_config_options(source_file_path, kernel_source_path)
            if not config_options:
                config_options = self.find_makefiles_config_options(
                    re.sub(r'_[^_]+', '', source_file_path), kernel_source_path
                )
            if not config_options:
                parent_source_dir = os.path.dirname(source_file_path)
                while parent_source_dir != "" and parent_source_dir != kernel_source_path and not config_options:
                    config_options = self.find_makefiles_config_options(parent_source_dir, kernel_source_path)
                    parent_source_dir = os.path.dirname(parent_source_dir)

            if config_options:
                all_config_options.update(config_options)
                if self.verbose:
                    print(f"Config options for {sourcefile}: {config_options}")
        
        # Handle architecture-specific issues
        if architecture_issues and not all_config_options:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.COMPONENT_NOT_PRESENT,
                detail=f"Affects non-ARM architectures: {', '.join(architecture_issues)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        # If no configuration options found at all
        if not all_config_options:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.UNDER_INVESTIGATION,
                detail="Could not determine configuration requirements from Makefiles",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        if self.verbose:
            print(f"Total config options for CVE {cve_id}: {all_config_options}")
        return self.in_kernel_config(all_config_options, kernel_config)

    def is_kernel_related_cve(self, cve_info: CVEInfo) -> bool:
        """Determine if a CVE is related to the Linux kernel.
        
        This method analyzes various aspects of the CVE to determine if it's
        kernel-related, including:
        - CVE description text
        - Patch URLs pointing to kernel repositories
        - Reference URLs and tags
        
        Args:
            cve_info: CVE information object
            
        Returns:
            True if the CVE appears to be kernel-related, False otherwise
        """
        if not cve_info:
            return False
        
        # Check description for kernel-related keywords
        description = cve_info.description.lower() if cve_info.description else ""
        
        # Strong kernel indicators in description
        kernel_keywords = [
            'linux kernel', 'kernel', 'vmlinux', 'kmod', 'ksymtab',
            'syscall', 'system call', 'kernel module', 'kernel space',
            'kernel driver', 'kernel panic', 'kernel oops', 'kernel crash',
            'kernel memory', 'kernel buffer', 'kernel stack', 'kernel heap',
            'kernel thread', 'kernel process', 'kernel scheduler',
            'kernel filesystem', 'kernel network', 'kernel security',
            'kernel vulnerability', 'kernel bug', 'kernel fix',
            'kernel patch', 'kernel source', 'kernel code',
            'kernel implementation', 'kernel subsystem',
            'device driver', 'kernel api', 'kernel function',
            'kernel data structure', 'kernel interface'
        ]
        
        # Check for kernel keywords in description
        if any(keyword in description for keyword in kernel_keywords):
            if self.verbose:
                print(f"CVE {cve_info.cve_id} identified as kernel-related based on description keywords")
            return True
        
        # Check patch URLs for kernel repositories
        if cve_info.patch_urls:
            kernel_repo_indicators = [
                'git.kernel.org',
                'github.com/torvalds/linux',
                'lore.kernel.org',
                'patchwork.kernel.org',
                'kernel.org',
                'linux-kernel',
                'stable/linux'
            ]
            
            for patch_url in cve_info.patch_urls:
                if any(indicator in patch_url.lower() for indicator in kernel_repo_indicators):
                    if self.verbose:
                        print(f"CVE {cve_info.cve_id} identified as kernel-related based on patch URL: {patch_url}")
                    return True
        
        # Additional heuristics based on CVE ID patterns
        # Some CVE databases have patterns for kernel CVEs
        cve_id = cve_info.cve_id
        
        # If we have patch URLs but none are clearly kernel-related,
        # and description doesn't contain kernel keywords, likely not kernel-related
        if cve_info.patch_urls and not any(keyword in description for keyword in [
            'linux', 'kernel', 'driver', 'syscall', 'module'
        ]):
            # Check for non-kernel indicators
            non_kernel_indicators = [
                'apache', 'nginx', 'mysql', 'postgresql', 'mongodb',
                'nodejs', 'python', 'java', 'php', 'ruby', 'perl',
                'docker', 'kubernetes', 'openssl', 'gnutls',
                'firefox', 'chrome', 'webkit', 'browser',
                'wordpress', 'drupal', 'joomla',
                'windows', 'macos', 'android', 'ios'
            ]
            
            if any(indicator in description for indicator in non_kernel_indicators):
                if self.verbose:
                    print(f"CVE {cve_info.cve_id} identified as non-kernel-related based on software indicators")
                return False
        
        # If no clear indicators either way, err on the side of caution
        # and include it (conservative approach)
        if self.verbose:
            print(f"CVE {cve_info.cve_id} classification unclear - including for analysis (conservative approach)")
        
        return True

    def _process_cve_parallel(self, cve: Dict, kernel_config: List[str], kernel_source_path: str) -> Tuple[str, VulnerabilityAnalysis]:
        """Process a single CVE for parallel execution.
        
        Args:
            cve: CVE vulnerability data
            kernel_config: List of enabled kernel configuration options
            kernel_source_path: Path to kernel source directory
            
        Returns:
            Tuple of (CVE ID, VulnerabilityAnalysis)
        """
        cve_id = cve.get('id', 'Unknown')
        try:
            analysis = self.check_kernel_config(cve, kernel_config, kernel_source_path)
            if analysis is None:
                # CVE was skipped due to patch checking failure
                return cve_id, None
            return cve_id, analysis
        except Exception as e:
            error_analysis = VulnerabilityAnalysis(
                state=VulnerabilityState.UNDER_INVESTIGATION,
                detail=f"Processing error: {str(e)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
            return cve_id, error_analysis

    @timed_method
    def _batch_process_vulnerabilities(self, vulnerabilities: List[Dict], kernel_config: List[str], 
                                     kernel_source_path: str, reanalyse: bool = False, 
                                     cve_id: Optional[str] = None) -> Dict[str, VulnerabilityAnalysis]:
        """Process vulnerabilities in parallel batches for better performance.
        
        Args:
            vulnerabilities: List of vulnerability data
            kernel_config: List of enabled kernel configuration options
            kernel_source_path: Path to kernel source directory
            reanalyse: Whether to re-analyze all vulnerabilities
            cve_id: Specific CVE ID to process
            
        Returns:
            Dictionary mapping CVE IDs to analysis results
        """
        results = {}
        vulnerabilities_to_process = []
        
        # Filter vulnerabilities to process
        for vulnerability in vulnerabilities:
            vuln_id = vulnerability.get('id', 'Unknown')
            
            if cve_id and cve_id != vuln_id:
                continue
            
            if not reanalyse and 'analysis' in vulnerability:
                if self.verbose:
                    print(f"Skipping CVE {vuln_id} as it already has an analysis.")
                continue
            
            vulnerabilities_to_process.append(vulnerability)
        
        if not vulnerabilities_to_process:
            return results
        
        print(f"Processing {len(vulnerabilities_to_process)} vulnerabilities in parallel...")
        
        # Process in parallel with limited workers to avoid overwhelming the system
        with ThreadPoolExecutor(max_workers=min(self.MAX_PARALLEL_WORKERS, len(vulnerabilities_to_process))) as executor:
            # Submit all tasks
            future_to_cve = {
                executor.submit(self._process_cve_parallel, vuln, kernel_config, kernel_source_path): vuln.get('id', 'Unknown')
                for vuln in vulnerabilities_to_process
            }
            
            # Track progress
            total_vulnerabilities = len(vulnerabilities_to_process)
            completed_count = 0
            
            # Collect results as they complete
            for future in as_completed(future_to_cve):
                original_cve_id = future_to_cve[future]
                completed_count += 1
                progress_percentage = (completed_count * 100) // total_vulnerabilities
                
                try:
                    cve_id, analysis = future.result(timeout=300)  # 5 minute timeout per CVE
                    if analysis is not None:
                        results[cve_id] = analysis
                        
                        if self.verbose:
                            print(f"[{completed_count}/{total_vulnerabilities}] ({progress_percentage}%) Completed CVE {cve_id}: {analysis.state.value}")
                        else:
                            status_emoji = "✅" if analysis.state == VulnerabilityState.NOT_AFFECTED else "⚠️"
                            print(f"[{completed_count}/{total_vulnerabilities}] {status_emoji} CVE {cve_id}: {analysis.state.value}")
                    else:
                        # CVE was skipped due to patch checking failure
                        if self.verbose:
                            print(f"[{completed_count}/{total_vulnerabilities}] ({progress_percentage}%) Skipped CVE {cve_id}: patch checking failed")
                        else:
                            print(f"[{completed_count}/{total_vulnerabilities}] ⏩ CVE {cve_id}: skipped")
                        
                except Exception as e:
                    print(f"[{completed_count}/{total_vulnerabilities}] ❌ Error processing CVE {original_cve_id}: {e}")
                    results[original_cve_id] = VulnerabilityAnalysis(
                        state=VulnerabilityState.UNDER_INVESTIGATION,
                        detail=f"Processing timeout or error: {str(e)}",
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    )
        
        return results

    @timed_method
    def update_analysis_state(self, vex_data: Dict, kernel_config: List[str], kernel_source_path: str, 
                            reanalyse: bool = False, cve_id: Optional[str] = None) -> Dict:
        """Update analysis state for vulnerabilities in VEX data with parallel processing.
        
        Args:
            vex_data: VEX data dictionary
            kernel_config: List of enabled kernel configuration options
            kernel_source_path: Path to kernel source directory
            reanalyse: Whether to re-analyze all vulnerabilities or skip existing analyses
            cve_id: Specific CVE ID to process (if provided)
            
        Returns:
            Updated VEX data dictionary with enhanced analysis information
        """
        print("Updating analysis state for vulnerabilities...")
        
        vulnerabilities = vex_data.get('vulnerabilities', [])
        total_vulnerabilities = len(vulnerabilities)
        processed_count = 0
        skipped_count = 0
        error_count = 0
        
        print(f"Found {total_vulnerabilities} vulnerabilities to analyze...")
        
        # Filter vulnerabilities to process
        vulnerabilities_to_process = []
        indices_to_process = []
        
        for i, vulnerability in enumerate(vulnerabilities):
            vuln_id = vulnerability.get('id', 'Unknown')
            
            if cve_id and cve_id != vuln_id:
                continue
            
            if not reanalyse and 'analysis' in vulnerability:
                if self.verbose:
                    print(f"Skipping CVE {vuln_id} as it already has an analysis.")
                skipped_count += 1
                continue
            
            vulnerabilities_to_process.append(vulnerability)
            indices_to_process.append(i)
        
        if not vulnerabilities_to_process:
            print("No vulnerabilities to process.")
            return vex_data
        
        print(f"Will process {len(vulnerabilities_to_process)} vulnerabilities (skipping {skipped_count} already analyzed)")
        
        # Process vulnerabilities sequentially to prevent API rate limiting (parallel only for very large batches)
        if len(vulnerabilities_to_process) > 10 and not self.verbose:
            print(f"Processing {len(vulnerabilities_to_process)} vulnerabilities in parallel...")
            try:
                parallel_results = self._batch_process_vulnerabilities(
                    vulnerabilities_to_process, kernel_config, kernel_source_path, reanalyse, cve_id
                )
                
                # Apply results to original vulnerabilities list
                for original_index, vulnerability in zip(indices_to_process, vulnerabilities_to_process):
                    vuln_id = vulnerability.get('id', 'Unknown')
                    if vuln_id in parallel_results:
                        vulnerabilities[original_index]['analysis'] = parallel_results[vuln_id].to_dict()
                        processed_count += 1
                    
            except Exception as e:
                print(f"Parallel processing failed, falling back to sequential: {e}")
                # Fall back to sequential processing
                total_fallback = len(vulnerabilities_to_process)
                for idx, (vulnerability, original_index) in enumerate(zip(vulnerabilities_to_process, indices_to_process), 1):
                    vuln_id = vulnerability.get('id', 'Unknown')
                    progress_percentage = (idx * 100) // total_fallback
                    print(f"[{idx}/{total_fallback}] ({progress_percentage}%) Fallback processing CVE {vuln_id}")
                    
                    try:
                        analysis = self.check_kernel_config(vulnerability, kernel_config, kernel_source_path)
                        if analysis is not None:
                            vulnerability['analysis'] = analysis.to_dict()
                            processed_count += 1
                            
                            status_emoji = "✅" if analysis.state == VulnerabilityState.NOT_AFFECTED else "⚠️"
                            print(f"{status_emoji} CVE {vuln_id}: {analysis.state.value}")
                        else:
                            # CVE was skipped due to patch checking failure
                            skipped_count += 1
                            print(f"⏩ CVE {vuln_id}: skipped")
                    except Exception as inner_e:
                        error_count += 1
                        print(f"❌ Error processing CVE {vuln_id}: {inner_e}")
                        vulnerability['analysis'] = VulnerabilityAnalysis(
                            state=VulnerabilityState.UNDER_INVESTIGATION,
                            detail=f"Processing error: {str(inner_e)}",
                            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                        ).to_dict()
        else:
            # Sequential processing for small numbers, single CVE, or verbose mode
            total_to_process = len(vulnerabilities_to_process)
            processing_mode = "verbose mode" if self.verbose else f"small batch ({total_to_process} CVEs)"
            print(f"Using sequential processing for {processing_mode}")
            
            for idx, vulnerability in enumerate(vulnerabilities_to_process, 1):
                vuln_id = vulnerability.get('id', 'Unknown')
                progress_percentage = (idx * 100) // total_to_process
                print(f"[{idx}/{total_to_process}] ({progress_percentage}%) Checking CVE {vuln_id}")
                
                try:
                    analysis = self.check_kernel_config(vulnerability, kernel_config, kernel_source_path)
                    if analysis is not None:
                        vulnerability['analysis'] = analysis.to_dict()
                        processed_count += 1
                        
                        if self.verbose:
                            print(f"Analysis completed for CVE {vuln_id}: {analysis.state.value}")
                        else:
                            status_emoji = "✅" if analysis.state == VulnerabilityState.NOT_AFFECTED else "⚠️"
                            print(f"{status_emoji} CVE {vuln_id}: {analysis.state.value}")
                    else:
                        # CVE was skipped due to patch checking failure
                        skipped_count += 1
                        if self.verbose:
                            print(f"Skipped CVE {vuln_id}: patch checking failed")
                        else:
                            print(f"⏩ CVE {vuln_id}: skipped")
                        
                except Exception as e:
                    error_count += 1
                    print(f"Error processing CVE {vuln_id}: {e}")
                    if self.verbose:
                        import traceback
                        traceback.print_exc()
                    
                    vulnerability['analysis'] = VulnerabilityAnalysis(
                        state=VulnerabilityState.UNDER_INVESTIGATION,
                        detail=f"Processing error: {str(e)}",
                        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    ).to_dict()
        
        # Add processing summary
        print(f"\nProcessing Summary:")
        print(f"  Processed: {processed_count}")
        print(f"  Skipped: {skipped_count}")
        print(f"  Errors: {error_count}")
        print(f"  Total: {len(vulnerabilities)}")
        
        # Add metadata to VEX data
        if 'metadata' not in vex_data:
            vex_data['metadata'] = {}
        
        vex_data['metadata'].update({
            'last_analysis': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            'processed_count': processed_count,
            'error_count': error_count,
            'tool_version': '2.0',
            'analysis_method': 'kernel_config_analysis'
        })
        
        return vex_data

    @timed_method
    def save_vex_file(vex_data: Dict, file_path: str) -> None:
        """Save updated VEX data to a new file.
        
        Args:
            vex_data: VEX data dictionary to save
            file_path: Original file path (new file will have .new extension)
        """
        new_file_path = f"{file_path}.new"
        print(f"Saving updated VEX file to {new_file_path}...")
        with open(new_file_path, 'w') as file:
            json.dump(vex_data, file, indent=4)
        print(f"Updated VEX file saved to {new_file_path}")

    def generate_vulnerability_report(self, vex_data: Dict) -> Dict:
        """Generate a comprehensive vulnerability analysis report.
        
        Args:
            vex_data: VEX data dictionary with analysis results
            
        Returns:
            Dictionary containing vulnerability report statistics
        """
        vulnerabilities = vex_data.get('vulnerabilities', [])
        
        
        report = {
            'total_vulnerabilities': len(vulnerabilities),
            'analyzed_vulnerabilities': 0,
            'not_affected': 0,
            'affected': 0,
            'under_investigation': 0,
            'severity_breakdown': {},
            'justification_breakdown': {},
            'high_priority_cves': [],
            'configuration_issues': []
        }
        
        for vuln in vulnerabilities:
            analysis = vuln.get('analysis', {})
            if not analysis:
                continue
                
            report['analyzed_vulnerabilities'] += 1
            state = analysis.get('state', 'unknown')
            
            # Count by state
            if state == 'not_affected':
                report['not_affected'] += 1
            elif state == 'affected':
                report['affected'] += 1
            elif state == 'under_investigation':
                report['under_investigation'] += 1
            
            # Severity breakdown
            severity = vuln.get('severity', 'unknown')
            report['severity_breakdown'][severity] = report['severity_breakdown'].get(severity, 0) + 1
            
            # Justification breakdown
            justification = analysis.get('justification', 'none')
            report['justification_breakdown'][justification] = report['justification_breakdown'].get(justification, 0) + 1
            
            # High priority CVEs (affected with high/critical severity)
            if state == 'affected' and severity in ['HIGH', 'CRITICAL']:
                report['high_priority_cves'].append({
                    'cve_id': vuln.get('id'),
                    'severity': severity,
                    'detail': analysis.get('detail', '')
                })
            
            # Configuration issues
            if analysis.get('justification') == 'requires_configuration':
                report['configuration_issues'].append({
                    'cve_id': vuln.get('id'),
                    'detail': analysis.get('detail', '')
                })
        
        return report
    
    def validate_vex_data(self, vex_data: Dict) -> List[str]:
        """Validate VEX data structure and return list of issues.
        
        Args:
            vex_data: VEX data dictionary to validate
            
        Returns:
            List of validation issues found
        """
        issues = []
        
        if 'vulnerabilities' not in vex_data:
            issues.append("Missing 'vulnerabilities' field in VEX data")
            return issues
        
        vulnerabilities = vex_data['vulnerabilities']
        if not isinstance(vulnerabilities, list):
            issues.append("'vulnerabilities' field must be a list")
            return issues
        
        for i, vuln in enumerate(vulnerabilities):
            if not isinstance(vuln, dict):
                issues.append(f"Vulnerability {i}: must be a dictionary")
                continue
            
            if 'id' not in vuln:
                issues.append(f"Vulnerability {i}: missing 'id' field")
            elif not vuln['id'].startswith('CVE-'):
                issues.append(f"Vulnerability {i}: ID should start with 'CVE-'")
            
            # Validate analysis if present
            if 'analysis' in vuln:
                analysis = vuln['analysis']
                if not isinstance(analysis, dict):
                    issues.append(f"Vulnerability {i}: 'analysis' must be a dictionary")
                    continue
                
                if 'state' not in analysis:
                    issues.append(f"Vulnerability {i}: analysis missing 'state' field")
                elif analysis['state'] not in [s.value for s in VulnerabilityState]:
                    issues.append(f"Vulnerability {i}: invalid analysis state '{analysis['state']}'")
                
                if 'justification' in analysis:
                    justification = analysis['justification']
                    if justification not in [j.value for j in Justification]:
                        issues.append(f"Vulnerability {i}: invalid justification '{justification}'")
        
        return issues

    def print_vulnerability_summary(self, report: Dict) -> None:
        """Print a formatted vulnerability analysis summary.
        
        Args:
            report: Vulnerability report dictionary from generate_vulnerability_report
        """
        print("\n" + "="*60)
        print("VULNERABILITY ANALYSIS SUMMARY")
        print("="*60)
        
        print(f"Total Vulnerabilities: {report['total_vulnerabilities']}")
        print(f"Analyzed: {report['analyzed_vulnerabilities']}")
        print(f"Not Affected: {report['not_affected']}")
        print(f"Affected: {report['affected']}")
        print(f"Under Investigation: {report['under_investigation']}")
        
        if report['severity_breakdown']:
            print(f"\nSeverity Breakdown:")
            for severity, count in sorted(report['severity_breakdown'].items()):
                print(f"  {severity}: {count}")
        
        if report['justification_breakdown']:
            print(f"\nJustification Breakdown:")
            for justification, count in sorted(report['justification_breakdown'].items()):
                print(f"  {justification}: {count}")
        
        if report['high_priority_cves']:
            print(f"\nHigh Priority CVEs ({len(report['high_priority_cves'])}):")
            for cve in report['high_priority_cves'][:5]:  # Show first 5
                print(f"  ⚠️  {cve['cve_id']} ({cve['severity']})")
        
        if report['configuration_issues']:
            print(f"\nConfiguration Issues ({len(report['configuration_issues'])}):")
            for issue in report['configuration_issues'][:3]:  # Show first 3
                print(f"  🔧 {issue['cve_id']}: {issue['detail'][:60]}...")
        
        print("="*60)

    def test_webdriver_functionality(self) -> bool:
        """Test WebDriver functionality with a simple page load.
        
        Returns:
            True if WebDriver works correctly, False otherwise
        """
        driver = None
        try:
            if self.verbose:
                print("Testing WebDriver functionality...")
            
            # Validate WebDriver path before attempting to use it
            if not self.edge_driver_path:
                if self.verbose:
                    print("Edge WebDriver path is not set")
                return False
            
            if not os.path.isfile(self.edge_driver_path):
                if self.verbose:
                    print(f"Edge WebDriver not found at: {self.edge_driver_path}")
                return False
            
            service = Service(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Edge(service=service, options=options)
            driver.set_page_load_timeout(10)
            
            # Test with a simple, reliable page
            driver.get("data:text/html,<html><body><h1>WebDriver Test</h1></body></html>")
            
            title = driver.title
            if self.verbose:
                print(f"WebDriver test successful. Page title: '{title}'")
            
            return True
            
        except SessionNotCreatedException as e:
            print(f"WebDriver session creation failed: {e}")
            print("Troubleshooting tips:")
            print("  1. Ensure Microsoft Edge browser is installed")
            print("  2. Download the correct WebDriver version from:")
            print("     https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/")
            print("  3. Ensure WebDriver version matches your Edge browser version")
            return False
        except Exception as e:
            print(f"WebDriver test failed: {e}")
            return False
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass  # Ignore cleanup errors

    def _compile_config_patterns(self) -> List:
        """Compile regex patterns for better performance."""
        return [
            # Pattern for extracting source files from patches
            re.compile(r'diff --git a/(.*)\.c b/'),
            # Pattern for #ifdef CONFIG_* 
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            # Pattern for #if defined(CONFIG_*)
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            # Pattern for IS_ENABLED(CONFIG_*)
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            # Pattern for obj-$(CONFIG_*) assignments
            re.compile(r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?='),
            # Pattern for CONFIG references in general
            re.compile(r'CONFIG_[A-Z0-9_]+')
        ]

    def _compile_patch_patterns(self) -> List:
        """Compile patch-specific regex patterns."""
        return [
            # Diff pattern for source files
            re.compile(r'diff --git a/(.*)\.c b/'),
            # ifdef pattern
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            # if defined pattern
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            # IS_ENABLED pattern
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)')
        ]

    def _compile_advanced_config_patterns(self) -> Dict[str, List]:
        """Compile advanced regex patterns for ultra-fast config detection."""
        return {
            'primary': [
                # Direct obj-$(CONFIG_*) patterns (most common)
                re.compile(r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?=\s*.*?\.o\b', re.IGNORECASE),
                # Composite object patterns
                re.compile(r'([a-zA-Z0-9_-]+)-objs-\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
                # Direct CONFIG assignment patterns
                re.compile(r'^(CONFIG_[A-Z0-9_]+)\s*[=:]', re.MULTILINE),
            ],
            'conditional': [
                # ifdef/ifndef patterns
                re.compile(r'ifdef\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(r'ifndef\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                # ifeq/ifneq patterns
                re.compile(r'ifeq\s*\(\s*\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
                re.compile(r'ifneq\s*\(\s*\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
            ],
            'source_hints': [
                # C source file preprocessor patterns
                re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(r'#if\s+defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)', re.IGNORECASE),
                re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)', re.IGNORECASE),
                re.compile(r'IS_BUILTIN\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)', re.IGNORECASE),
            ]
        }

    def _compile_optimized_source_patterns(self) -> Dict[str, re.Pattern]:
        """Compile optimized patterns for source file analysis."""
        return {
            'c_files': re.compile(r'\.c\s*$', re.IGNORECASE),
            'header_files': re.compile(r'\.h\s*$', re.IGNORECASE),
            'makefile_names': re.compile(r'^(Makefile|Kbuild|makefile|GNUmakefile)$', re.IGNORECASE),
            'config_reference': re.compile(r'CONFIG_[A-Z0-9_]+'),
            'diff_source': re.compile(r'diff --git a/(.*?\.c)\s+b/', re.IGNORECASE),
        }

    def _get_directory_priority(self, directory_path: str, source_file_path: str) -> int:
        """Calculate search priority for a directory based on relevance to source file.
        
        Higher numbers = higher priority (searched first)
        """
        if directory_path in self._directory_priority_cache:
            return self._directory_priority_cache[directory_path]
        
        priority = 0
        dir_name = os.path.basename(directory_path)
        source_dir = os.path.dirname(source_file_path)
        source_base = os.path.splitext(os.path.basename(source_file_path))[0]
        
        # Highest priority: exact directory match
        if directory_path == source_dir:
            priority = 1000
        # High priority: parent directory
        elif directory_path == os.path.dirname(source_dir):
            priority = 800
        # Medium-high priority: directory name matches source base name
        elif dir_name == source_base or source_base in dir_name:
            priority = 600
        # Medium priority: common kernel subsystem directories
        elif any(subsys in directory_path for subsys in [
            'drivers/net', 'drivers/usb', 'drivers/pci', 'drivers/scsi',
            'fs/', 'net/', 'sound/', 'crypto/', 'security/'
        ]):
            priority = 400
        # Lower priority: architecture-specific (but not ARM)
        elif 'arch/' in directory_path and 'arm' not in directory_path.lower():
            priority = 100
        # Lowest priority: documentation, tools, etc.
        elif any(skip in directory_path for skip in [
            'Documentation', 'tools', 'scripts', '.git'
        ]):
            priority = 10
        else:
            priority = 200  # Default priority
        
        # Cache the result
        self._directory_priority_cache[directory_path] = priority
        return priority

    def _find_makefiles_fast(self, kernel_source_path: str, source_file_path: str) -> List[str]:
        """Ultra-fast makefile discovery using smart search ordering."""
        cache_key = f"makefiles:{source_file_path}"
        if cache_key in self._makefile_location_cache:
            self._cache_hits['makefile'] += 1
            return self._makefile_location_cache[cache_key]
        
        self._cache_misses['makefile'] += 1
        makefiles = []
        
        # Priority-ordered search starting from source file directory
        source_dir = os.path.dirname(source_file_path)
        search_candidates = []
        
        # Build priority-ordered candidate directories
        current_dir = source_dir
        while current_dir and current_dir != kernel_source_path:
            search_candidates.append((current_dir, self._get_directory_priority(current_dir, source_file_path)))
            current_dir = os.path.dirname(current_dir)
        
        # Add kernel root with medium priority
        search_candidates.append((kernel_source_path, 300))
        
        # Sort by priority (highest first)
        search_candidates.sort(key=lambda x: x[1], reverse=True)
        
        # Search in priority order
        makefile_names = ['Makefile', 'Kbuild']
        for directory, _ in search_candidates[:20]:  # Limit to top 20 candidates
            for makefile_name in makefile_names:
                makefile_path = os.path.join(directory, makefile_name)
                if os.path.exists(makefile_path):
                    makefiles.append(makefile_path)
                    if len(makefiles) >= 10:  # Limit total makefiles for performance
                        break
            if len(makefiles) >= 10:
                break
        
        # Cache the result
        self._makefile_location_cache[cache_key] = makefiles
        
        # Limit cache size
        if len(self._makefile_location_cache) > 500:
            # Remove oldest 100 entries
            oldest_keys = list(self._makefile_location_cache.keys())[:100]
            for key in oldest_keys:
                del self._makefile_location_cache[key]
        
        return makefiles

    def _extract_configs_ultra_fast(self, content: str, source_file_name: str, 
                                   makefile_vars: Dict[str, str]) -> Set[str]:
        """Ultra-fast configuration extraction using optimized patterns."""
        config_options = set()
        
        # Quick exit if no CONFIG references
        if 'CONFIG_' not in content:
            return config_options
        
        base_name = os.path.splitext(source_file_name)[0]
        expanded_content = self._expand_makefile_variables(content, makefile_vars)
        
        # Use precompiled advanced patterns
        patterns = self._advanced_config_patterns
        
        # Primary patterns (highest confidence)
        for pattern in patterns['primary']:
            for match in pattern.finditer(expanded_content):
                if any(target in match.group(0) for target in [base_name, source_file_name]):
                    for group_idx in range(1, pattern.groups + 1 if pattern.groups else 1):
                        group_val = match.group(group_idx)
                        if group_val and group_val.startswith('CONFIG_'):
                            config_options.add(group_val)
        
        # Conditional patterns (medium confidence)
        if base_name in expanded_content or source_file_name in expanded_content:
            for pattern in patterns['conditional']:
                for match in pattern.finditer(expanded_content):
                    config_options.add(match.group(1))
        
        return config_options

    def _analyze_source_file_ultra_fast(self, source_file_path: str) -> Set[str]:
        """Ultra-fast source file analysis with aggressive caching."""
        # Check cache first
        if source_file_path in self._source_analysis_cache:
            self._cache_hits['source'] += 1
            return self._source_analysis_cache[source_file_path]
        
        self._cache_misses['source'] += 1
        config_options = set()
        
        try:
            # Use cached file content
            content = self._get_cached_file_content(source_file_path)
            if not content:
                self._source_analysis_cache[source_file_path] = config_options
                return config_options
            
            # Quick check for CONFIG references
            if 'CONFIG_' not in content:
                self._source_analysis_cache[source_file_path] = config_options
                return config_options
            
            # Use optimized patterns for source analysis
            source_patterns = self._advanced_config_patterns['source_hints']
            
            for pattern in source_patterns:
                for match in pattern.finditer(content):
                    config_options.add(match.group(1))
            
            if config_options and self.verbose:
                print(f"Ultra-fast source analysis found {len(config_options)} configs in {source_file_path}")
        
        except Exception as e:
            if self.verbose:
                print(f"Error in ultra-fast source analysis for {source_file_path}: {e}")
        
        # Cache the result
        self._source_analysis_cache[source_file_path] = config_options

        # Limit cache size for memory management
        if len(self._source_analysis_cache) > self.SOURCE_ANALYSIS_CACHE_SIZE:
            # Remove oldest 200 entries
            oldest_keys = list(self._source_analysis_cache.keys())[:200]
            for key in oldest_keys:
                del self._source_analysis_cache[key]
        
        return config_options

    def print_performance_stats(self):
        """Print detailed performance statistics."""
        print("\n=== Performance Statistics ===")
        
        # Cache statistics
        print("\nCache Performance:")
        for cache_name in ['makefile', 'config', 'source', 'path']:
            hits = self._cache_hits.get(cache_name, 0)
            misses = self._cache_misses.get(cache_name, 0)
            total = hits + misses
            hit_rate = (hits / total * 100) if total > 0 else 0
            print(f"  {cache_name}: {hits} hits, {misses} misses ({hit_rate:.1f}% hit rate)")
        
        # Cache sizes
        print("\nCache Sizes:")
        cache_info = {
            'makefile': len(self._makefile_cache),
            'config': len(self._config_cache),
            'kconfig': len(self._kconfig_cache),
            'path': len(self._path_cache),
            'source_analysis': len(self._source_analysis_cache),
            'directory_priority': len(self._directory_priority_cache),
            'makefile_location': len(self._makefile_location_cache),
            'file_content': len(self._file_content_cache)
        }
        
        for cache_name, size in cache_info.items():
            print(f"  {cache_name}: {size} entries")
        
        total_cached_entries = sum(cache_info.values())
        print(f"\nTotal cached entries: {total_cached_entries}")


@timed_method
def main():
    """Main entry point with performance tracking."""
    perf_tracker.start_timer('total_execution')
    
    parser = argparse.ArgumentParser(
        description='VEX Kernel Checker - Analyze CVE vulnerabilities against kernel configurations\n\n'
                   'By default, only processes CVEs that do not have an existing analysis. '
                   'Use --reanalyse to re-analyze CVEs that already have results.',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--vex-file', required=True, help='Path to VEX JSON file')
    parser.add_argument('--kernel-config', required=True, help='Path to kernel config file (.config)')
    parser.add_argument('--kernel-source', required=True, help='Path to kernel source directory')
    parser.add_argument('--output', help='Output file path (default: update VEX file in place)')
    parser.add_argument('--reanalyse', action='store_true', 
                        help='Re-analyze all vulnerabilities, including those with existing analysis (default: only analyze CVEs without analysis)')
    parser.add_argument('--cve-id', help='Process only specific CVE ID')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--config-only', action='store_true', help='Disable patch checking and perform config-only analysis (faster but less accurate)')
    parser.add_argument('--api-key', help='NVD API key for CVE details (enables patch checking when combined with --edge-driver)')
    parser.add_argument('--edge-driver', help='Path to Edge WebDriver executable (enables patch checking when combined with --api-key)')
    parser.add_argument('--clear-cache', action='store_true', help='Clear all internal caches before starting analysis')
    parser.add_argument('--performance-stats', action='store_true', help='Show detailed performance statistics')
    parser.add_argument('--analyze-all-cves', action='store_true', help='Analyze all CVEs regardless of kernel relevance (default: only analyze kernel-related CVEs)')
    
    args = parser.parse_args()
    
    # No validation needed - patch checking will be automatically enabled if both api_key and edge_driver are provided
    # and automatically disabled otherwise. The --config-only flag explicitly disables patch checking.
    
    # Validate input files
    if not os.path.exists(args.vex_file):
        print(f"Error: VEX file not found: {args.vex_file}")
        return 1
    
    if not os.path.exists(args.kernel_config):
        print(f"Error: Kernel config file not found: {args.kernel_config}")
        return 1
    
    if not os.path.exists(args.kernel_source):
        print(f"Error: Kernel source directory not found: {args.kernel_source}")
        return 1
    
    try:
        # Load VEX data
        perf_tracker.start_timer('load_vex_data')
        with open(args.vex_file, 'r') as f:
            vex_data = json.load(f)
        perf_tracker.end_timer('load_vex_data')
        
        # Load kernel config
        perf_tracker.start_timer('load_kernel_config')
        with open(args.kernel_config, 'r') as f:
            kernel_config_lines = f.readlines()
        
        # Extract enabled config options
        kernel_config = []
        for line in kernel_config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        perf_tracker.end_timer('load_kernel_config')
        
        print(f"Loaded {len(kernel_config)} enabled kernel config options")
        
        # Initialize checker with performance tracking
        perf_tracker.start_timer('initialize_checker')
        checker = VexKernelChecker(
            verbose=args.verbose, 
            api_key=args.api_key,
            edge_driver_path=args.edge_driver,
            disable_patch_checking=args.config_only,
            analyze_all_cves=args.analyze_all_cves
        )
        perf_tracker.end_timer('initialize_checker')
        
        # Clear caches if requested
        if args.clear_cache:
            print("Clearing all caches...")
            checker.clear_all_caches()
        
        # Update analysis state
        perf_tracker.start_timer('vulnerability_analysis')
        updated_vex_data = checker.update_analysis_state(
            vex_data, kernel_config, args.kernel_source, 
            reanalyse=args.reanalyse, cve_id=args.cve_id
        )
        perf_tracker.end_timer('vulnerability_analysis')
        
        # Save results
        perf_tracker.start_timer('save_results')
        output_file = args.output or args.vex_file
        with open(output_file, 'w') as f:
            json.dump(updated_vex_data, f, indent=2)
        perf_tracker.end_timer('save_results')
        
        print(f"\nUpdated VEX data saved to: {output_file}")
        
        # Show performance statistics
        if args.verbose or args.performance_stats:
            checker.print_performance_stats()
        
        perf_tracker.end_timer('total_execution')
        
        if args.performance_stats:
            perf_tracker.print_summary()
        
        return 0
        
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
