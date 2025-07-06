#!/usr/bin/env python3
"""
VEX Kernel Checker - A production-ready tool for analyzing CVE vulnerabilities against kernel configurations.

This script processes VEX (Vulnerability Exploitability eXchange) files and checks
whether CVEs are applicable to a given kernel configuration by analyzing patch files
and Makefile configurations with intelligent filtering.

Key Features:
- Fetches CVE details from NVD API with rate limiting
- Downloads patches from GitHub, kernel.org, and other sources
- Analyzes Makefiles to determine required configuration options
- Filters out build-time, debug, and irrelevant configuration options
- Architecture-aware analysis (ARM64, x86, etc.)
- XEN-aware filtering for non-XEN systems
- Parallel processing for performance
- Comprehensive caching for efficiency

MIT License - Copyright (c) 2025
"""

import argparse
import json
import os
import re
import requests
import sys
import time
import glob
import traceback
import signal
import threading
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Union, Any

# Selenium imports for web scraping
try:
    from selenium import webdriver
    from selenium.webdriver.edge.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, SessionNotCreatedException, NoSuchElementException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    print("Warning: Selenium not available. WebDriver functionality disabled.")


# Global settings for performance monitoring
ENABLE_TIMING_OUTPUT = False  # Set to True to show detailed method timing

def timed_method(func):
    """Decorator to time method execution for performance monitoring."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time
        
        # Only print timing if globally enabled or if instance has detailed_timing enabled
        show_timing = ENABLE_TIMING_OUTPUT
        
        # Check if this is a method call and the instance has detailed timing enabled
        if not show_timing and args and hasattr(args[0], '__class__'):
            instance = args[0]
            if hasattr(instance, 'detailed_timing') and instance.detailed_timing:
                show_timing = True
        
        if show_timing:
            # Get class name if this is a method
            class_name = ""
            if args and hasattr(args[0], '__class__'):
                class_name = f"{args[0].__class__.__name__}."
            
            print(f"⏱️  {class_name}{func.__name__}: {duration:.3f}s")
        
        return result
    return wrapper


class PerformanceTracker:
    """Advanced performance tracking for optimization and debugging."""
    
    def __init__(self):
        self.timings = {}
        self.cache_stats = {}
        
    def start_timer(self, name: str):
        """Start timing an operation."""
        self.timings[name] = {'start': time.time()}
        
    def end_timer(self, name: str):
        """End timing an operation."""
        if name in self.timings:
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
    """Enumeration of possible vulnerability states according to CycloneDX v1.6."""
    RESOLVED = "resolved"
    RESOLVED_WITH_PEDIGREE = "resolved_with_pedigree"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


class Justification(Enum):
    """Enumeration of justification reasons for vulnerability state according to CycloneDX v1.6."""
    CODE_NOT_PRESENT = "code_not_present"
    CODE_NOT_REACHABLE = "code_not_reachable"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"
    PROTECTED_BY_COMPILER = "protected_by_compiler"
    PROTECTED_AT_RUNTIME = "protected_at_runtime"
    PROTECTED_AT_PERIMETER = "protected_at_perimeter"
    PROTECTED_BY_MITIGATING_CONTROL = "protected_by_mitigating_control"


class Response(Enum):
    """Enumeration of response actions for vulnerabilities."""
    CAN_NOT_FIX = "can_not_fix"
    WILL_NOT_FIX = "will_not_fix"
    UPDATE = "update"
    ROLLBACK = "rollback"
    WORKAROUND_AVAILABLE = "workaround_available"


@dataclass
class VulnerabilityAnalysis:
    """Data class representing the analysis of a vulnerability."""
    state: VulnerabilityState
    justification: Optional[Justification] = None
    response: Optional[Response] = None
    detail: Optional[str] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"state": self.state.value}
        if self.justification:
            result["justification"] = self.justification.value
        if self.response:
            result["response"] = self.response.value
        if self.detail:
            result["detail"] = self.detail
        if self.timestamp:
            result["timestamp"] = self.timestamp
        return result


@dataclass
class CVEInfo:
    """Data class for CVE information."""
    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    patch_urls: Optional[List[str]] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None


# Global interrupt flag for graceful shutdown
_interrupt_requested = threading.Event()

def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print(f"\n🛑 Interrupt signal received (signal {signum}). Gracefully shutting down...")
    _interrupt_requested.set()

def check_interrupt():
    """Check if an interrupt has been requested."""
    if _interrupt_requested.is_set():
        raise KeyboardInterrupt("Analysis interrupted by user request")

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


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
    
    # Configuration constants for performance optimization
    API_RATE_LIMIT_DELAY = 1.5  # seconds between API calls (NVD requires delays)
    API_MAX_RETRIES = 3
    API_BACKOFF_FACTOR = 2.0
    MAX_PARALLEL_WORKERS = 2  # Limited to prevent NVD API rate limiting
    MAKEFILE_CACHE_SIZE = 5000  # Increased for better hit rate
    CONFIG_CACHE_SIZE = 2000
    SOURCE_ANALYSIS_CACHE_SIZE = 1000
    MAX_MAKEFILE_SEARCH_FILES = 100  # Focus on most relevant files
    MAX_KCONFIG_RECURSION_DEPTH = 20  # Prevent deep recursion
    MAX_INCLUDE_FILES_PER_MAKEFILE = 5  # Limit processing scope
    
    # Class constants for intelligent filtering
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
    
    # Performance optimization flags
    ENABLE_AGGRESSIVE_CACHING = True
    ENABLE_PARALLEL_FILE_IO = True
    ENABLE_SMART_SEARCH_ORDERING = True
    
    def __init__(self, verbose: bool = False, api_key: Optional[str] = None, 
                 edge_driver_path: Optional[str] = None, disable_patch_checking: bool = False, 
                 analyze_all_cves: bool = False, arch: Optional[str] = None, 
                 arch_config: Optional[str] = None, detailed_timing: bool = False):
        """Initialize the VEX Kernel Checker."""
        self.verbose = verbose
        self.detailed_timing = detailed_timing  # Controls whether to show method timing
        self.api_key = api_key
        self.edge_driver_path = edge_driver_path
        # Enable patch checking by default (NVD API doesn't require API key)
        # API key is optional and only provides higher rate limits
        self.check_patches = not disable_patch_checking
        self.analyze_all_cves = analyze_all_cves
        self.arch = arch
        self.arch_config = arch_config
        
        # Initialize caches
        self._makefile_cache = {}
        self._config_cache = {}
        self._kconfig_cache = {}
        self._path_cache = {}
        self._source_analysis_cache = {}
        self._directory_priority_cache = {}
        self._makefile_location_cache = {}
        self._file_content_cache = {}
        
        # Performance tracking
        self._cache_hits = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        self._cache_misses = {'makefile': 0, 'config': 0, 'source': 0, 'path': 0}
        self._processed_cves = set()
        
        # Compile regex patterns for performance
        self._config_patterns = self._compile_config_patterns()
        self._patch_patterns = self._compile_patch_patterns()
        self._advanced_config_patterns = self._compile_advanced_config_patterns()
        
        if self.verbose:
            print(f"VEX Kernel Checker initialized:")
            print(f"  Patch checking: {'enabled' if self.check_patches else 'disabled'}")
            print(f"  API key: {'provided' if self.api_key else 'not provided'}")
            if not self.api_key:
                print(f"  Note: NVD API key not required but provides higher rate limits")
            print(f"  WebDriver: {'available' if self.edge_driver_path else 'not available'}")

    def _compile_config_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for configuration extraction."""
        return [
            re.compile(r'diff --git a/(.*)\.c b/'),
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?='),
            re.compile(r'CONFIG_[A-Z0-9_]+')
        ]

    def _compile_patch_patterns(self) -> List[re.Pattern]:
        """Compile patch-specific regex patterns."""
        return [
            re.compile(r'diff --git a/(.*)\.c b/'),
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)')
        ]

    def _compile_advanced_config_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile advanced regex patterns for config detection."""
        return {
            'primary': [
                re.compile(r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?=\s*.*?\.o\b', re.IGNORECASE),
                re.compile(r'([a-zA-Z0-9_-]+)-objs-\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
                re.compile(r'^(CONFIG_[A-Z0-9_]+)\s*[=:]', re.MULTILINE),
            ],
            'conditional': [
                re.compile(r'ifdef\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(r'ifeq\s*\(\s*\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
            ],
            'source_hints': [
                re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)', re.IGNORECASE),
            ]
        }

    def _get_cached_file_content(self, file_path: str) -> str:
        """Get file content with caching."""
        if file_path in self._file_content_cache:
            return self._file_content_cache[file_path]
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self._file_content_cache[file_path] = content
            
            # Limit cache size
            if len(self._file_content_cache) > 1000:
                oldest_keys = list(self._file_content_cache.keys())[:200]
                for key in oldest_keys:
                    del self._file_content_cache[key]
            
            return content
        except Exception as e:
            if self.verbose:
                print(f"Error reading file {file_path}: {e}")
            return ""

    def _get_cached_makefile_vars(self, makefile_path: str) -> Dict[str, str]:
        """Get makefile variables with caching."""
        if makefile_path in self._makefile_cache:
            return self._makefile_cache[makefile_path]
        
        makefile_vars = {}
        try:
            content = self._get_cached_file_content(makefile_path)
            for line in content.split('\n'):
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        var_name = parts[0].strip()
                        var_value = parts[1].strip()
                        makefile_vars[var_name] = var_value
            
            self._makefile_cache[makefile_path] = makefile_vars
            
            # Limit cache size
            if len(self._makefile_cache) > self.MAKEFILE_CACHE_SIZE:
                oldest_keys = list(self._makefile_cache.keys())[:100]
                for key in oldest_keys:
                    del self._makefile_cache[key]
                    
        except Exception as e:
            if self.verbose:
                print(f"Error parsing makefile {makefile_path}: {e}")
        
        return makefile_vars

    def clear_all_caches(self):
        """Clear all caches and reset counters."""
        self._makefile_cache.clear()
        self._config_cache.clear()
        self._kconfig_cache.clear()
        self._path_cache.clear()
        self._source_analysis_cache.clear()
        self._directory_priority_cache.clear()
        self._makefile_location_cache.clear()
        self._file_content_cache.clear()
        
        # Reset performance counters
        for cache_type in self._cache_hits:
            self._cache_hits[cache_type] = 0
            self._cache_misses[cache_type] = 0
        
        self._processed_cves.clear()
        
        if self.verbose:
            print("All caches cleared")

    # Static validation methods
    @staticmethod
    def validate_file_path(file_path: str) -> str:
        """Validate and normalize file path."""
        if not file_path or not isinstance(file_path, str):
            raise ValueError("File path must be a non-empty string")
        
        normalized_path = os.path.abspath(file_path)
        if not os.path.exists(normalized_path):
            raise FileNotFoundError(f"File not found: {normalized_path}")
        
        return normalized_path

    @staticmethod
    def validate_directory_path(dir_path: str) -> str:
        """Validate and normalize directory path."""
        if not dir_path or not isinstance(dir_path, str):
            raise ValueError("Directory path must be a non-empty string")
        
        normalized_path = os.path.abspath(dir_path)
        if not os.path.isdir(normalized_path):
            raise NotADirectoryError(f"Directory not found: {normalized_path}")
        
        return normalized_path

    @staticmethod
    def validate_api_key(api_key: str) -> str:
        """Validate NVD API key format."""
        if not api_key or not isinstance(api_key, str):
            raise ValueError("API key must be a non-empty string")
        
        # Basic format validation for NVD API key
        if len(api_key) < 30:
            raise ValueError("API key appears to be too short")
        
        return api_key.strip()

    @staticmethod
    def validate_edge_driver_path(driver_path: str) -> str:
        """Validate Edge WebDriver path."""
        if not driver_path or not isinstance(driver_path, str):
            raise ValueError("Edge driver path must be a non-empty string")
        
        normalized_path = os.path.abspath(driver_path)
        if not os.path.exists(normalized_path):
            raise FileNotFoundError(f"Edge driver not found: {normalized_path}")
        
        if not os.access(normalized_path, os.X_OK):
            raise PermissionError(f"Edge driver is not executable: {normalized_path}")
        
        return normalized_path

    # File loading utilities
    @staticmethod
    def load_vex_file(file_path: str) -> Dict:
        """Load and validate VEX file."""
        validated_path = VexKernelChecker.validate_file_path(file_path)
        
        with open(validated_path, 'r') as f:
            return json.load(f)

    @staticmethod
    def load_kernel_config(config_path: str) -> List[str]:
        """Load kernel configuration file."""
        validated_path = VexKernelChecker.validate_file_path(config_path)
        
        config_options = []
        with open(validated_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract CONFIG_* options
                    if line.startswith('CONFIG_') and '=' in line:
                        config_name = line.split('=')[0]
                        config_options.append(config_name)
        
        return config_options

    @staticmethod
    def _replace_multiple_substrings(text: str, replacements: Dict[str, str]) -> str:
        """Replace multiple substrings in text efficiently."""
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def _interruptible_sleep(self, duration: float):
        """Sleep for the given duration while checking for interrupts."""
        chunks = max(1, int(duration / 0.5))  # Sleep in 0.5s chunks
        chunk_duration = duration / chunks
        
        for _ in range(chunks):
            time.sleep(chunk_duration)
            check_interrupt()

    def _format_eta(self, eta_seconds: float) -> str:
        """Format ETA (estimated time remaining) into a human-readable string."""
        if eta_seconds <= 0:
            return "Done"
        
        if eta_seconds < 60:
            return f"{eta_seconds:.0f}s"
        elif eta_seconds < 3600:
            minutes = int(eta_seconds // 60)
            seconds = int(eta_seconds % 60)
            return f"{minutes}m {seconds}s"
        else:
            hours = int(eta_seconds // 3600)
            remaining_seconds = eta_seconds % 3600
            minutes = int(remaining_seconds // 60)
            if hours >= 24:
                days = int(hours // 24)
                hours = int(hours % 24)
                return f"{days}d {hours}h {minutes}m"
            else:
                return f"{hours}h {minutes}m"

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
        # Check for interrupt before starting
        check_interrupt()
        
        # Rate limiting - ensure proper delays between API calls
        with self._api_rate_lock:
            current_time = time.time()
            time_since_last_call = current_time - self._last_global_api_call
            
            if time_since_last_call < self.API_RATE_LIMIT_DELAY:
                sleep_time = self.API_RATE_LIMIT_DELAY - time_since_last_call
                if self.verbose:
                    print(f"Rate limiting: sleeping {sleep_time:.2f}s before NVD API call")
                
                # Sleep in small chunks to allow interrupts
                chunks = int(sleep_time / 0.5) + 1
                for _ in range(chunks):
                    time.sleep(min(0.5, sleep_time))
                    sleep_time -= 0.5
                    check_interrupt()
                    if sleep_time <= 0:
                        break
            
            self._last_global_api_call = time.time()

        # Check cache first
        if cve_id in self._config_cache:
            self._cache_hits['config'] += 1
            return self._config_cache[cve_id]

        self._cache_misses['config'] += 1

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
                        self._config_cache[cve_id] = cve_info
                        
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

    def _url_ignored(self, url: str) -> bool:
        """Check if URL should be ignored based on domain patterns."""
        return any(ignored_domain in url for ignored_domain in self.IGNORED_URLS)

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
        
        # Add the original URL only if it's not already included and not in templates
        if (original_url not in alternatives and 
            original_url not in github_templates and 
            original_url not in kernel_org_templates):
            alternatives.append(original_url)
        
        # Add kernel.org URLs
        alternatives.extend(kernel_org_templates)
        
        return alternatives

    def _extract_commit_id_from_url(self, url: str) -> Optional[str]:
        """Extract Git commit ID from various URL formats."""
        # Pattern for GitHub commit URLs
        github_patterns = [
            r'github\.com/[^/]+/[^/]+/commit/([a-f0-9]{8,40})',
            r'github\.com/[^/]+/[^/]+/commit/([a-f0-9]{8,40})\.patch',
            r'github\.com/[^/]+/[^/]+/commit/([a-f0-9]{8,40})\.diff',
        ]
        
        # Pattern for kernel.org URLs
        kernel_org_patterns = [
            r'git\.kernel\.org/.*[?&]id=([a-f0-9]{8,40})',
            r'git\.kernel\.org/.*commit.*[?&]h=([a-f0-9]{8,40})',
            r'git\.kernel\.org/stable/c/([a-f0-9]{8,40})',  # git.kernel.org/stable/c/COMMIT_ID
            r'git\.kernel\.org/.*/c/([a-f0-9]{8,40})',      # any git.kernel.org/*/c/COMMIT_ID format
        ]
        
        # Pattern for lore.kernel.org
        lore_patterns = [
            r'lore\.kernel\.org/[^/]+/([a-f0-9]{8,40})',
        ]
        
        all_patterns = github_patterns + kernel_org_patterns + lore_patterns
        
        for pattern in all_patterns:
            match = re.search(pattern, url)
            if match:
                commit_id = match.group(1)
                # Validate commit ID length (Git commit IDs are 8-40 hex chars)
                if len(commit_id) >= 8 and re.match(r'^[a-f0-9]+$', commit_id):
                    return commit_id
        
        return None

    def _convert_kernel_org_to_github(self, original_url: str, commit_id: str) -> Optional[str]:
        """Convert kernel.org URLs to GitHub URLs if the commit exists on GitHub."""
        # Only process kernel.org URLs
        if 'git.kernel.org' not in original_url:
            return None
        
        # Try the most common GitHub URL format for Linux kernel
        github_url = f"https://github.com/torvalds/linux/commit/{commit_id}"
        
        # Check if the GitHub URL exists with a simple HEAD request
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
        if not SELENIUM_AVAILABLE:
            return None
            
        driver = None
        try:
            service = Service(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            
            driver = webdriver.Edge(service=service, options=options)
            driver.set_page_load_timeout(30)
            
            if self.verbose:
                print(f"Loading patch URL: {patch_url}")
            
            driver.get(patch_url)
            
            # Try multiple selectors to find patch content
            selectors = [
                'pre.highlight',          # GitHub patch view
                'pre',                    # Generic pre tag
                '.blob-code-inner',       # GitHub blob view
                '.file-diff-content',     # Generic diff content
                'table.diff-table',       # Table-based diff
                '.diff-content',          # Generic diff class
                'body'                    # Last resort - entire body
            ]
            
            for selector in selectors:
                try:
                    element = driver.find_element(By.CSS_SELECTOR, selector)
                    content = element.text
                    
                    if content and ('diff --git' in content or 'index ' in content or '@@' in content):
                        if self.verbose:
                            print(f"Successfully extracted patch content using selector: {selector}")
                        return content
                        
                except Exception:
                    continue
            
            # If no specific selectors work, try the page source
            page_source = driver.page_source
            if page_source and ('diff --git' in page_source or 'index ' in page_source):
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
        
        # Try direct HTTP request to original URL
        try:
            if self.verbose:
                print(f"Attempting direct HTTP request to: {patch_url}")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/plain, text/html, application/json, */*'
            }
            
            response = requests.get(patch_url, headers=headers, timeout=30)
            response.raise_for_status()
            
            content = response.text
            if content and ('diff --git' in content or 'index ' in content or '@@' in content):
                if self.verbose:
                    print("Successfully fetched patch via direct HTTP")
                return content
                
        except Exception as e:
            if self.verbose:
                print(f"Direct HTTP request failed: {e}")
        
        # Try alternative URLs (GitHub URLs will be prioritized in the list)
        alternative_urls = self.get_alternative_patch_urls(patch_url)
        for alt_url in alternative_urls[:5]:  # Try top 5 alternatives
            if alt_url == patch_url:  # Skip original URL
                continue
                
            try:
                response = requests.get(alt_url, headers=headers, timeout=20)
                response.raise_for_status()
                
                content = response.text
                if content and ('diff --git' in content or 'index ' in content or '@@' in content):
                    if self.verbose:
                        print(f"Successfully fetched patch from alternative URL: {alt_url}")
                    return content
                    
            except Exception as e:
                if self.verbose:
                    print(f"Alternative URL {alt_url} failed: {e}")
                continue
        
        # Final fallback: try Selenium WebDriver
        if SELENIUM_AVAILABLE and self.edge_driver_path:
            if self.verbose:
                print("Trying WebDriver as final fallback")
            return self.fetch_patch_with_selenium(patch_url)
        
        return None

    @staticmethod
    def fetch_patch_from_github(commit_id: str) -> Optional[str]:
        """Fetch patch content from GitHub API."""
        try:
            github_urls = [
                f"https://api.github.com/repos/torvalds/linux/commits/{commit_id}",
                f"https://patch-diff.githubusercontent.com/raw/torvalds/linux/pull/{commit_id}.patch"
            ]
            
            for url in github_urls:
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    if 'api.github.com' in url:
                        # Parse API response
                        data = response.json()
                        if 'files' in data:
                            # Construct patch from API data
                            patch_lines = []
                            for file_data in data['files']:
                                if 'patch' in file_data:
                                    patch_lines.append(file_data['patch'])
                            return '\n'.join(patch_lines)
                    else:
                        # Direct patch content
                        return response.text
                        
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
            re.compile(r'\+\+\+ b/(.*)'),  # +++ b/filename
            re.compile(r'--- a/(.*)'),    # --- a/filename  
            re.compile(r'diff --git a/(.*) b/'),  # diff --git a/file b/file
        ]
        
        for line in patch_info.split('\n'):
            for pattern in patterns:
                matches = pattern.findall(line)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match else ""
                    
                    # Clean and validate the file path
                    clean_path = match.strip()
                    if clean_path and clean_path.endswith('.c'):
                        # Apply path replacements
                        clean_path = self._replace_multiple_substrings(clean_path, self.PATH_REPLACEMENTS)
                        source_files.add(clean_path)
        
        if self.verbose and source_files:
            print(f"Extracted {len(source_files)} source files from patch")
            
        return source_files

    @timed_method
    def extract_config_options_from_makefile(self, makefile_path: str, source_file_name: str) -> Set[str]:
        """Extract configuration options from Makefile using recursive analysis."""
        processed_files = set()
        return self._extract_config_recursive_optimized(makefile_path, source_file_name, processed_files)

    def _extract_config_recursive_optimized(self, makefile_path: str, source_file_name: str, processed_files: Set[str]) -> Set[str]:
        """Optimized recursive configuration extraction with caching."""
        # Prevent infinite recursion
        if makefile_path in processed_files or len(processed_files) > self.MAX_INCLUDE_FILES_PER_MAKEFILE:
            return set()
        
        processed_files.add(makefile_path)
        
        # Check cache first
        cache_key = f"{makefile_path}:{source_file_name}"
        if cache_key in self._config_cache:
            self._cache_hits['config'] += 1
            return self._config_cache[cache_key]
        
        self._cache_misses['config'] += 1
        config_options = set()
        
        try:
            makefile_vars = self._get_cached_makefile_vars(makefile_path)
            content = self._get_cached_file_content(makefile_path)
            
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Extract configs from this line
                line_configs = self._extract_configs_from_line(line, source_file_name, makefile_path, makefile_vars)
                config_options.update(line_configs)
                
                # Handle includes
                if line.startswith('include') or 'include' in line:
                    include_patterns = self._resolve_include_pattern(line, makefile_path, makefile_vars)
                    for include_path in include_patterns[:self.MAX_INCLUDE_FILES_PER_MAKEFILE]:
                        if os.path.exists(include_path) and include_path not in processed_files:
                            included_configs = self._extract_config_recursive_optimized(
                                include_path, source_file_name, processed_files.copy()
                            )
                            config_options.update(included_configs)
            
            # Cache the result
            self._config_cache[cache_key] = config_options
            
        except Exception as e:
            if self.verbose:
                print(f"Error processing makefile {makefile_path}: {e}")
        
        return config_options

    def _resolve_include_pattern(self, include_pattern: str, makefile_path: str, makefile_vars: dict) -> List[str]:
        """Resolve include patterns to actual file paths."""
        resolved_paths = []
        
        # Extract include path from line
        include_match = re.search(r'include\s+(.+)', include_pattern)
        if not include_match:
            return resolved_paths
        
        include_path = include_match.group(1).strip()
        
        # Expand variables
        expanded_path = self._expand_makefile_variables(include_path, makefile_vars)
        
        # Handle relative paths
        makefile_dir = os.path.dirname(makefile_path)
        
        if not os.path.isabs(expanded_path):
            full_path = os.path.join(makefile_dir, expanded_path)
        else:
            full_path = expanded_path
        
        # Handle wildcards
        if '*' in expanded_path or '?' in expanded_path:
            try:
                glob_matches = glob.glob(full_path)
                resolved_paths.extend(glob_matches[:self.MAX_INCLUDE_FILES_PER_MAKEFILE])
            except Exception:
                pass
        else:
            if os.path.exists(full_path):
                resolved_paths.append(full_path)
        
        return resolved_paths

    def _extract_configs_from_line(self, line: str, source_file_name: str, makefile_path: str, makefile_vars: dict) -> Set[str]:
        """Extract configuration options from a single Makefile line."""
        config_options = set()
        
        # Expand variables in the line
        expanded_line = self._expand_makefile_variables(line, makefile_vars)
        
        # Check if line references our source file
        has_source_ref = source_file_name in expanded_line or source_file_name.replace('.c', '.o') in expanded_line
        
        # Skip lines that don't reference our file and aren't conditional
        if not has_source_ref and not any(keyword in expanded_line.lower() for keyword in ['ifdef', 'ifeq', 'ifneq']):
            return config_options
        
        # Use all advanced patterns
        for pattern_group in self._advanced_config_patterns.values():
            for pattern in pattern_group:
                matches = pattern.findall(expanded_line)
                for match in matches:
                    if isinstance(match, tuple):
                        config_option = match[0] if match else ""
                    else:
                        config_option = match
                    
                    if config_option and config_option.startswith('CONFIG_'):
                        config_options.add(config_option)
        
        # Special handling for conditional compilation
        if any(keyword in expanded_line for keyword in ['ifdef', 'ifeq', 'ifneq']):
            # Extract configs from conditional statements
            config_matches = re.findall(r'CONFIG_[A-Z0-9_]+', expanded_line)
            config_options.update(config_matches)
        
        return config_options

    def _expand_makefile_variables(self, line: str, makefile_vars: dict) -> str:
        """Expand Makefile variables in a line.
        
        Args:
            line: The line to expand
            makefile_vars: Dictionary of variable definitions
        """
        expanded = line
        
        # Handle $(VAR) and ${VAR} syntax
        def replace_var(match):
            var_name = match.group(1)
            return makefile_vars.get(var_name, match.group(0))
        
        expanded = re.sub(r'\$\(([^)]+)\)', replace_var, expanded)
        expanded = re.sub(r'\$\{([^}]+)\}', replace_var, expanded)
        
        return expanded

    @timed_method
    def _find_kconfig_dependencies(self, config_option: str, kernel_source_path: str) -> Set[str]:
        """Find Kconfig dependencies for a configuration option."""
        dependencies = set()
        
        # Cache check
        cache_key = f"{config_option}:{kernel_source_path}"
        if cache_key in self._kconfig_cache:
            self._cache_hits['config'] += 1
            return self._kconfig_cache[cache_key]
        
        self._cache_misses['config'] += 1
        
        # Look for Kconfig files
        kconfig_patterns = [
            'Kconfig*',
            '*/Kconfig*',
            '**/Kconfig*'
        ]
        
        kconfig_files = []
        for pattern in kconfig_patterns:
            try:
                matches = glob.glob(os.path.join(kernel_source_path, pattern), recursive=True)
                kconfig_files.extend(matches[:50])  # Limit to prevent excessive processing
            except Exception:
                continue
        
        # Parse Kconfig files
        for kconfig_file in kconfig_files[:20]:  # Process only first 20 files
            try:
                file_deps = self._parse_kconfig_file(kconfig_file, config_option)
                dependencies.update(file_deps)
            except Exception as e:
                if self.verbose:
                    print(f"Error parsing Kconfig file {kconfig_file}: {e}")
        
        # Cache result
        self._kconfig_cache[cache_key] = dependencies
        return dependencies

    def _parse_kconfig_file(self, kconfig_path: str, target_config: str) -> Set[str]:
        """Parse a Kconfig file to find dependencies."""
        dependencies = set()
        
        try:
            content = self._get_cached_file_content(kconfig_path)
            lines = content.split('\n')
            
            current_config = None
            in_target_config = False
            
            for line in lines:
                line = line.strip()
                
                # Look for the target config definition
                if line.startswith('config '):
                    current_config = line.split()[1] if len(line.split()) > 1 else None
                    in_target_config = (current_config == target_config.replace('CONFIG_', ''))
                
                # Extract dependencies if we're in the target config
                if in_target_config:
                    if line.startswith('depends on ') or line.startswith('select '):
                        dep_line = line.replace('depends on ', '').replace('select ', '')
                        # Extract CONFIG_ options from dependency line
                        config_matches = re.findall(r'\b[A-Z0-9_]+\b', dep_line)
                        for match in config_matches:
                            if not match.startswith('CONFIG_'):
                                dependencies.add(f'CONFIG_{match}')
                            else:
                                dependencies.add(match)
                
                # Reset when we hit another config
                if line.startswith('config ') and not in_target_config:
                    current_config = None
        
        except Exception:
            pass
        
        return dependencies

    @timed_method
    def find_makefile_config_options(self, source_file_path: str, makefile_path: str, kernel_source_path: str) -> Set[str]:
        """Find configuration options for a source file from a specific Makefile."""
        # Extract just the filename
        source_file_name = os.path.basename(source_file_path)
        
        # Get configs from this Makefile
        config_options = self.extract_config_options_from_makefile(makefile_path, source_file_name)
        
        # Add Kconfig dependencies
        all_configs = set(config_options)
        for config in list(config_options):
            dependencies = self._find_kconfig_dependencies(config, kernel_source_path)
            all_configs.update(dependencies)
        filtered_configs = self._filter_relevant_config_options(all_configs)
        if self.verbose and filtered_configs:
            print(f"Found {len(filtered_configs)} config options for {source_file_name}")
        
        return filtered_configs

    @timed_method
    def find_makefiles_config_options(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Find all relevant Makefiles and extract configuration options."""
        config_options = set()
        
        # Cache check
        cache_key = f"makefiles:{source_file_path}:{kernel_source_path}"
        if cache_key in self._config_cache:
            self._cache_hits['config'] += 1
            return self._config_cache[cache_key]
        
        self._cache_misses['config'] += 1
        
        # Use optimized makefile finding
        makefiles = self._find_makefiles_fast(kernel_source_path, source_file_path)
        
        # Process makefiles in priority order
        for makefile_path in makefiles[:self.MAX_MAKEFILE_SEARCH_FILES]:
            try:
                makefile_configs = self.find_makefile_config_options(
                    source_file_path, makefile_path, kernel_source_path
                )
                config_options.update(makefile_configs)
            except Exception as e:
                if self.verbose:
                    print(f"Error processing makefile {makefile_path}: {e}")
        
        # Add advanced source-based analysis
        advanced_configs = self._advanced_config_search(source_file_path, kernel_source_path)
        config_options.update(advanced_configs)
        
        # Cache result
        self._config_cache[cache_key] = config_options
        
        if self.verbose:
            print(f"Total {len(config_options)} config options found for {source_file_path}")
        
        return config_options

    def _analyze_related_makefiles(self, search_dir: str, source_file_path: str, kernel_source_path: str, config_options: Set[str]):
        """Analyze related Makefiles in the same directory tree."""
        try:
            for root, dirs, files in os.walk(search_dir):
                # Limit depth to prevent excessive searching
                depth = root.replace(search_dir, '').count(os.sep)
                if depth > 3:
                    dirs.clear()
                    continue
                
                for filename in files:
                    if filename in ['Makefile', 'Kbuild', 'Makefile.am']:
                        makefile_path = os.path.join(root, filename)
                        try:
                            makefile_configs = self.find_makefile_config_options(
                                source_file_path, makefile_path, kernel_source_path
                            )
                            config_options.update(makefile_configs)
                        except Exception:
                            continue
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing related makefiles in {search_dir}: {e}")

    def _find_makefiles_fast(self, kernel_source_path: str, source_file_path: str) -> List[str]:
        """Fast Makefile discovery with intelligent prioritization."""
        makefiles = []
        
        # Cache check
        cache_key = f"makefiles_fast:{kernel_source_path}:{source_file_path}"
        if cache_key in self._makefile_location_cache:
            self._cache_hits['makefile'] += 1
            return self._makefile_location_cache[cache_key]
        
        self._cache_misses['makefile'] += 1
        
        try:
            # Start from source file directory and work up
            rel_path = os.path.relpath(source_file_path, kernel_source_path)
            search_dirs = []
            
            # Add directories in priority order
            path_parts = rel_path.split(os.sep)
            for i in range(len(path_parts)):
                partial_path = os.path.join(kernel_source_path, *path_parts[:i+1])
                if os.path.isdir(partial_path):
                    search_dirs.append(partial_path)
                elif os.path.isfile(partial_path):
                    # Add parent directory of the file
                    search_dirs.append(os.path.dirname(partial_path))
            
            # Add root kernel source directory
            if kernel_source_path not in search_dirs:
                search_dirs.append(kernel_source_path)
            
            # Find Makefiles with priority scoring
            makefile_candidates = []
            
            for search_dir in search_dirs[:10]:  # Limit search depth
                try:
                    for filename in ['Makefile', 'Kbuild', 'Makefile.am']:
                        makefile_path = os.path.join(search_dir, filename)
                        if os.path.exists(makefile_path):
                            priority = self._get_directory_priority(search_dir, source_file_path)
                            makefile_candidates.append((makefile_path, priority))
                except Exception:
                    continue
            
            # Sort by priority (lower number = higher priority)
            makefile_candidates.sort(key=lambda x: x[1])
            makefiles = [path for path, _ in makefile_candidates]
            
            # Cache result
            self._makefile_location_cache[cache_key] = makefiles
            
        except Exception as e:
            if self.verbose:
                print(f"Error in fast makefile discovery: {e}")
        
        return makefiles

    def _get_directory_priority(self, directory_path: str, source_file_path: str) -> int:
        """Calculate priority score for a directory (lower = higher priority)."""
        # Check cache
        cache_key = f"{directory_path}:{source_file_path}"
        if cache_key in self._directory_priority_cache:
            return self._directory_priority_cache[cache_key]
        
        priority = 100  # Default priority
        
        try:
            # Higher priority for directories closer to source file
            rel_dir = os.path.relpath(directory_path, os.path.dirname(source_file_path))
            depth = rel_dir.count(os.sep)
            priority += depth * 10
            
            # Boost priority for certain directory patterns
            dir_name = os.path.basename(directory_path).lower()
            
            if dir_name in ['drivers', 'net', 'fs', 'sound', 'crypto']:
                priority -= 20  # Higher priority
            elif dir_name in ['arch', 'kernel', 'mm']:
                priority -= 10
            elif dir_name.startswith('test') or 'debug' in dir_name:
                priority += 50  # Lower priority
            
            # Boost if directory is in source file path
            if directory_path in source_file_path:
                priority -= 30
                
        except Exception:
            priority = 200  # Default priority
        
        # Cache the result
        self._directory_priority_cache[cache_key] = priority
        return priority

    @timed_method
    def check_kernel_config(self, cve: Dict, kernel_config: List[str], kernel_source_path: str) -> Optional[VulnerabilityAnalysis]:
        """
        Main method to check if a CVE affects the given kernel configuration.
        
        This method:
        1. Extracts or fetches CVE details
        2. Determines if the CVE is kernel-related
        3. Fetches patch information if available
        4. Analyzes configuration requirements
        5. Returns vulnerability analysis result
        """
        try:
            cve_id = cve.get('id', '')
            if not cve_id:
                if self.verbose:
                    print("Missing CVE ID - skipping analysis")
                return None  # Don't register analysis outcomes for missing CVE IDs
            
            if self.verbose:
                print(f"\n--- Analyzing {cve_id} ---")
            
            # Skip if already processed (for batch operations)
            if cve_id in self._processed_cves:
                if self.verbose:
                    print(f"Skipping {cve_id} - already processed")
                return None  # Don't register duplicate analysis outcomes
            
            self._processed_cves.add(cve_id)
            
            # Get CVE details
            cve_info = None
            # Always try to fetch from NVD API for authoritative CVE data and patch URLs
            # VEX files should contain CVE IDs only, patch URLs come from NVD
            if self.check_patches:
                if self.verbose:
                    print(f"🔍 Step 1/4: Fetching CVE details from NVD API...")
                cve_info = self.fetch_cve_details(cve_id)
                
                if not cve_info:
                    if self.verbose:
                        print(f"Could not fetch CVE details for {cve_id} - proceeding with VEX description analysis")
                    # Don't return None - continue with VEX description analysis
            
            # Check if kernel-related (unless analyzing all CVEs)
            if not self.analyze_all_cves and cve_info:
                if self.verbose:
                    print(f"🔍 Step 2/4: Checking if CVE is kernel-related...")
                if not self.is_kernel_related_cve(cve_info):
                    if self.verbose:
                        print(f"CVE {cve_id} is not kernel-related - skipping analysis")
                    return None  # Don't register non-kernel CVEs as analysis outcomes
            
            # Try to get patch URL and analyze
            if self.check_patches and cve_info:
                if self.verbose:
                    print(f"🔍 Step 3/4: Extracting and fetching patch content...")
                patch_url = self.extract_patch_url(cve_info)
                
                if patch_url:
                    if self.verbose:
                        print(f"Found patch URL: {patch_url}")
                    
                    # Fetch patch content
                    patch_info = self.fetch_patch_content_with_github_priority(patch_url)
                    
                    if patch_info:
                        # Early architecture compatibility check with patch content
                        arch_compatibility = self._check_architecture_compatibility(cve, cve_info, patch_info)
                        if not arch_compatibility['compatible']:
                            if self.verbose:
                                print(f"CVE not compatible with current architecture: {arch_compatibility['reason']}")
                            
                            return VulnerabilityAnalysis(
                                state=VulnerabilityState.NOT_AFFECTED,
                                justification=Justification.REQUIRES_ENVIRONMENT,
                                response=Response.WILL_NOT_FIX,
                                detail=arch_compatibility['detail'],
                                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                            )
                        
                        if self.verbose:
                            print(f"🔍 Step 4/4: Analyzing configuration requirements...")
                        # Extract source files from patch
                        source_files = self.extract_sourcefiles(patch_info)
                        
                        if source_files:
                            if self.verbose:
                                print(f"Analyzing {len(source_files)} source files from patch")
                            
                            all_config_options = set()
                            
                            # Analyze each source file
                            source_file_list = list(source_files)[:20]  # Limit to 20 files
                            
                            for i, source_file in enumerate(source_file_list):
                                try:
                                    if self.verbose and len(source_file_list) > 1:
                                        print(f"   📁 Analyzing file {i+1}/{len(source_file_list)}: {source_file}")
                                    
                                    # Try to find the file in kernel source
                                    full_source_path = os.path.join(kernel_source_path, source_file)
                                    
                                    if os.path.exists(full_source_path):
                                        file_configs = self.find_makefiles_config_options(
                                            full_source_path, kernel_source_path
                                        )
                                        all_config_options.update(file_configs)
                                        
                                        if self.verbose and file_configs:
                                            print(f"      ✅ Found {len(file_configs)} config options")
                                    else:
                                        if self.verbose:
                                            print(f"      ⚠️  Source file not found: {source_file}")
                                            
                                except Exception as e:
                                    if self.verbose:
                                        print(f"      ❌ Error analyzing {source_file}: {e}")
                                    continue
                            
                            # Also extract configs directly from patch
                            patch_configs = set()
                            for pattern in self._config_patterns:
                                matches = pattern.findall(patch_info)
                                for match in matches:
                                    if isinstance(match, tuple):
                                        config_option = match[0] if match else ""
                                    else:
                                        config_option = match
                                    
                                    if config_option and config_option.startswith('CONFIG_'):
                                        patch_configs.add(config_option)
                            
                            all_config_options.update(patch_configs)
                            
                            if all_config_options:
                                return self.in_kernel_config(all_config_options, kernel_config)
                            else:
                                if self.verbose:
                                    print("No configuration options found in patch analysis")
                        else:
                            if self.verbose:
                                print("No source files found in patch")
                    else:
                        if self.verbose:
                            print("Could not fetch patch content")
                else:
                    if self.verbose:
                        print("No patch URL found")
            
            # Driver-specific fallback analysis before general fallback
            cve_id = cve.get('id', '')
            description = cve.get('description', '').lower()
            
            # Generic driver-specific fallback based on description patterns
            driver_configs = self._infer_driver_configs_from_description(description)
            if driver_configs:
                if self.verbose:
                    print(f"Applying driver-specific fallback analysis for configs: {', '.join(driver_configs)}")
                
                return self.in_kernel_config(driver_configs, kernel_config)
            
            # Architecture compatibility check (fallback for non-patch cases)
            arch_compatibility = self._check_architecture_compatibility(cve, cve_info)
            if not arch_compatibility['compatible']:
                if self.verbose:
                    print(f"CVE not compatible with current architecture: {arch_compatibility['reason']}")
                
                return VulnerabilityAnalysis(
                    state=VulnerabilityState.NOT_AFFECTED,
                    justification=Justification.REQUIRES_ENVIRONMENT,
                    response=Response.WILL_NOT_FIX,
                    detail=arch_compatibility['detail'],
                    timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                )
            
            # Add other driver-specific fallbacks here as needed
            
            # General fallback analysis
            return VulnerabilityAnalysis(
                state=VulnerabilityState.IN_TRIAGE,
                justification=Justification.CODE_NOT_PRESENT,
                response=Response.CAN_NOT_FIX,
                detail="Unable to determine configuration requirements",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
            
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing {cve.get('id', 'unknown')}: {e}")
                traceback.print_exc()
            
            # Don't register analysis outcomes for errors - return None
            return None

    @timed_method
    def _infer_driver_configs_from_description(self, description: str) -> Set[str]:
        """
        Infer driver-specific configuration options from CVE description.
        
        This method analyzes CVE descriptions to identify driver-specific patterns
        and returns the relevant configuration options for those drivers.
        """
        driver_configs = set()
        description_lower = description.lower()
        
        # Driver-specific patterns and their associated configs
        driver_patterns = {
            # Network drivers
            'mlx5': {
                'CONFIG_MLX5_CORE', 'CONFIG_MLX5_CORE_EN', 'CONFIG_MLX5_EN_ARFS',
                'CONFIG_MLX5_EN_RXNFC', 'CONFIG_MLX5_INFINIBAND', 'CONFIG_NET',
                'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            'mlx4': {
                'CONFIG_MLX4_CORE', 'CONFIG_MLX4_EN', 'CONFIG_MLX4_INFINIBAND',
                'CONFIG_NET', 'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            'mellanox': {
                'CONFIG_MLX5_CORE', 'CONFIG_MLX4_CORE', 'CONFIG_NET',
                'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            'intel ethernet': {
                'CONFIG_E1000', 'CONFIG_E1000E', 'CONFIG_IGB', 'CONFIG_IGBVF',
                'CONFIG_IXGB', 'CONFIG_IXGBE', 'CONFIG_I40E', 'CONFIG_ICE',
                'CONFIG_NET', 'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            'intel wifi': {
                'CONFIG_IWLWIFI', 'CONFIG_IWLDVM', 'CONFIG_IWLMVM',
                'CONFIG_WIRELESS', 'CONFIG_WLAN', 'CONFIG_NET'
            },
            'broadcom': {
                'CONFIG_B44', 'CONFIG_BNX2', 'CONFIG_BNX2X', 'CONFIG_TIGON3',
                'CONFIG_NET', 'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            'realtek': {
                'CONFIG_8139TOO', 'CONFIG_R8169', 'CONFIG_NET',
                'CONFIG_ETHERNET', 'CONFIG_NETDEVICES'
            },
            
            # USB drivers  
            'usb': {
                'CONFIG_USB', 'CONFIG_USB_SUPPORT', 'CONFIG_USB_COMMON'
            },
            'usb-storage': {
                'CONFIG_USB_STORAGE', 'CONFIG_USB', 'CONFIG_SCSI'
            },
            'usbhid': {
                'CONFIG_USB_HID', 'CONFIG_HID', 'CONFIG_USB', 'CONFIG_INPUT'
            },
            
            # Bluetooth drivers
            'bluetooth': {
                'CONFIG_BT', 'CONFIG_BT_BREDR', 'CONFIG_BT_LE', 'CONFIG_NET'
            },
            'btusb': {
                'CONFIG_BT_HCIBTUSB', 'CONFIG_BT', 'CONFIG_USB'
            },
            
            # WiFi drivers
            'ath': {
                'CONFIG_ATH_COMMON', 'CONFIG_ATH9K', 'CONFIG_ATH10K',
                'CONFIG_WIRELESS', 'CONFIG_WLAN', 'CONFIG_NET'
            },
            'ath9k': {
                'CONFIG_ATH9K', 'CONFIG_ATH_COMMON', 'CONFIG_WIRELESS', 'CONFIG_WLAN'
            },
            'ath10k': {
                'CONFIG_ATH10K', 'CONFIG_ATH_COMMON', 'CONFIG_WIRELESS', 'CONFIG_WLAN'
            },
            'rtl8': {
                'CONFIG_RTL8180', 'CONFIG_RTL8187', 'CONFIG_RTL8192CE',
                'CONFIG_WIRELESS', 'CONFIG_WLAN', 'CONFIG_NET'
            },
            
            # Graphics drivers
            'drm': {
                'CONFIG_DRM', 'CONFIG_DRM_KMS_HELPER'
            },
            'i915': {
                'CONFIG_DRM_I915', 'CONFIG_DRM', 'CONFIG_PCI'
            },
            'amdgpu': {
                'CONFIG_DRM_AMDGPU', 'CONFIG_DRM', 'CONFIG_PCI'
            },
            'radeon': {
                'CONFIG_DRM_RADEON', 'CONFIG_DRM', 'CONFIG_PCI'
            },
            'nouveau': {
                'CONFIG_DRM_NOUVEAU', 'CONFIG_DRM', 'CONFIG_PCI'
            },
            
            # Sound drivers
            'alsa': {
                'CONFIG_SND', 'CONFIG_SOUND', 'CONFIG_SND_PCM'
            },
            'snd_': {
                'CONFIG_SND', 'CONFIG_SOUND'
            },
            
            # Storage drivers
            'nvme': {
                'CONFIG_BLK_DEV_NVME', 'CONFIG_NVME_CORE', 'CONFIG_PCI', 'CONFIG_BLOCK'
            },
            'scsi': {
                'CONFIG_SCSI', 'CONFIG_SCSI_LOWLEVEL', 'CONFIG_BLOCK'
            },
            'ahci': {
                'CONFIG_SATA_AHCI', 'CONFIG_ATA', 'CONFIG_BLOCK', 'CONFIG_PCI'
            },
            'mmc': {
                'CONFIG_MMC', 'CONFIG_MMC_BLOCK'
            },
            
            # Input drivers
            'input': {
                'CONFIG_INPUT', 'CONFIG_INPUT_KEYBOARD', 'CONFIG_INPUT_MOUSE'
            },
            'hid': {
                'CONFIG_HID', 'CONFIG_INPUT'
            },
            
            # Virtualization drivers
            'kvm': {
                'CONFIG_KVM', 'CONFIG_VIRTUALIZATION'
            },
            'xen': {
                'CONFIG_XEN', 'CONFIG_PARAVIRT'
            },
            'vmware': {
                'CONFIG_VMWARE_BALLOON', 'CONFIG_VMXNET3', 'CONFIG_NET'
            },
            
            # Filesystem drivers
            'ext4': {
                'CONFIG_EXT4_FS', 'CONFIG_EXT4_USE_FOR_EXT2', 'CONFIG_BLOCK'
            },
            'xfs': {
                'CONFIG_XFS_FS', 'CONFIG_BLOCK'
            },
            'btrfs': {
                'CONFIG_BTRFS_FS', 'CONFIG_BLOCK'
            },
            'nfs': {
                'CONFIG_NFS_FS', 'CONFIG_NFS_V4', 'CONFIG_NET'
            },
            
            # Security drivers
            'selinux': {
                'CONFIG_SECURITY_SELINUX', 'CONFIG_SECURITY'
            },
            'apparmor': {
                'CONFIG_SECURITY_APPARMOR', 'CONFIG_SECURITY'
            },
        }
        
        # Check for driver patterns in the description
        for pattern, configs in driver_patterns.items():
            if pattern in description_lower:
                driver_configs.update(configs)
                if self.verbose:
                    print(f"Found driver pattern '{pattern}' - adding configs: {', '.join(configs)}")
        
        # Additional pattern-based detection for specific subsystems
        
        # Detect network subsystem patterns
        net_patterns = ['net/', 'drivers/net/', 'network', 'netdev', 'skb', 'socket']
        if any(pattern in description_lower for pattern in net_patterns):
            driver_configs.update(['CONFIG_NET', 'CONFIG_NETDEVICES'])
        
        # Detect USB subsystem patterns  
        usb_patterns = ['usb', 'drivers/usb/', 'urb', 'endpoint']
        if any(pattern in description_lower for pattern in usb_patterns):
            driver_configs.update(['CONFIG_USB', 'CONFIG_USB_SUPPORT'])
        
        # Detect graphics subsystem patterns
        gpu_patterns = ['drm', 'gpu', 'graphics', 'display', 'framebuffer']
        if any(pattern in description_lower for pattern in gpu_patterns):
            driver_configs.update(['CONFIG_DRM', 'CONFIG_FB'])
        
        # Detect storage subsystem patterns
        storage_patterns = ['block', 'disk', 'storage', 'scsi', 'ata', 'ide']
        if any(pattern in description_lower for pattern in storage_patterns):
            driver_configs.update(['CONFIG_BLOCK'])
        
        # Detect wireless patterns
        wireless_patterns = ['wireless', 'wifi', 'wlan', '802.11']
        if any(pattern in description_lower for pattern in wireless_patterns):
            driver_configs.update(['CONFIG_WIRELESS', 'CONFIG_WLAN', 'CONFIG_NET'])
        
        # Detect sound patterns
        sound_patterns = ['sound', 'audio', 'alsa', 'pcm']
        if any(pattern in description_lower for pattern in sound_patterns):
            driver_configs.update(['CONFIG_SOUND', 'CONFIG_SND'])
        
        return driver_configs

    @timed_method
    def _check_architecture_compatibility(self, cve: Dict, cve_info: Optional['CVEInfo'] = None, patch_content: Optional[str] = None) -> Dict[str, Any]:
        """
        Check if a CVE is compatible with the detected system architecture.
        
        Args:
            cve: CVE dictionary with description and ID
            cve_info: Optional CVE info object with patch URLs 
            patch_content: Optional patch content for analysis
        
        Returns a dictionary with:
        - compatible: bool indicating if CVE is compatible
        - reason: string explaining why it's not compatible (if applicable)
        - detail: detailed description for the analysis
        """
        if not self.arch:
            # If no architecture detected, assume compatible
            return {
                'compatible': True,
                'reason': 'No architecture detected',
                'detail': 'Architecture compatibility could not be determined'
            }
        
        description = cve.get('description', '').lower()
        cve_id = cve.get('id', 'unknown')
        
        # Architecture-specific keywords that indicate CVE targets specific architectures
        arch_specific_patterns = {
            'x86': ['x86', 'intel', 'amd64', 'i386', 'i486', 'i586', 'i686'],
            'x86_64': ['x86_64', 'amd64', 'intel 64', 'x64'],
            'arm': ['arm32', 'armv7', 'armv6', 'arm cortex'],
            'arm64': ['arm64', 'aarch64', 'armv8'],
            'mips': ['mips', 'mips32', 'mips64'],
            'powerpc': ['powerpc', 'ppc', 'ppc32', 'ppc64'],
            'riscv': ['riscv', 'risc-v', 'riscv32', 'riscv64'],
            's390': ['s390', 's390x', 'ibm z'],
            'sparc': ['sparc', 'sparc32', 'sparc64', 'sun'],
            'alpha': ['alpha', 'dec alpha'],
            'ia64': ['ia64', 'itanium'],
            'm68k': ['m68k', 'motorola 68k'],
            'sh': ['superh', 'sh4'],
            'microblaze': ['microblaze'],
            'parisc': ['parisc', 'pa-risc'],
            'xtensa': ['xtensa']
        }
        
        # Check if CVE description mentions specific architectures
        mentioned_archs = []
        for arch, patterns in arch_specific_patterns.items():
            for pattern in patterns:
                if pattern in description:
                    mentioned_archs.append(arch)
                    break
        
        # Remove duplicates and normalize
        mentioned_archs = list(set(mentioned_archs))
        
        # Normalize current architecture for comparison
        current_arch_normalized = self.arch.lower()
        if current_arch_normalized == 'x86_64':
            current_arch_alternatives = ['x86_64', 'amd64', 'x64']
        elif current_arch_normalized == 'arm64':
            current_arch_alternatives = ['arm64', 'aarch64']
        elif current_arch_normalized == 'powerpc':
            current_arch_alternatives = ['powerpc', 'ppc']
        else:
            current_arch_alternatives = [current_arch_normalized]
        
        # Check for incompatibility
        if mentioned_archs:
            # Check if any mentioned architecture matches current architecture
            compatible = any(
                mentioned_arch in current_arch_alternatives or 
                any(alt in mentioned_arch for alt in current_arch_alternatives)
                for mentioned_arch in mentioned_archs
            )
            
            if not compatible:
                # Architecture mismatch found
                mentioned_archs_str = ', '.join(mentioned_archs)
                return {
                    'compatible': False,
                    'reason': f'CVE targets {mentioned_archs_str} but system uses {self.arch}',
                    'detail': f"CVE targets {mentioned_archs_str} architecture but this system uses {self.arch}. Architecture is not compatible."
                }
        
        # Check for architecture-specific file paths in common CVE patterns
        arch_path_patterns = {
            'x86': [r'arch/x86/', r'arch/i386/', r'/x86/', r'_x86_', r'intel'],
            'arm': [r'arch/arm/', r'/arm/', r'_arm_', r'cortex'],
            'arm64': [r'arch/arm64/', r'/arm64/', r'_arm64_', r'aarch64'],
            'mips': [r'arch/mips/', r'/mips/', r'_mips_'],
            'powerpc': [r'arch/powerpc/', r'arch/ppc/', r'/powerpc/', r'/ppc/', r'_ppc_'],
            'riscv': [r'arch/riscv/', r'/riscv/', r'_riscv_'],
            's390': [r'arch/s390/', r'/s390/', r'_s390_'],
            'sparc': [r'arch/sparc/', r'/sparc/', r'_sparc_'],
        }
        
        # Check for architecture-specific paths in description
        for arch, patterns in arch_path_patterns.items():
            if arch != current_arch_normalized:
                for pattern in patterns:
                    if pattern in description:
                        return {
                            'compatible': False,
                            'reason': f'CVE contains {arch}-specific paths but system uses {self.arch}',
                            'detail': f"CVE contains {arch}-specific code but this system uses {self.arch}. Architecture is not compatible."
                        }
        
        # Additional check for explicit architecture mentions in common CVE formats
        explicit_arch_mentions = [
            # Common patterns like "on x86" or "in ARM"
            r'\bon\s+(x86|arm|mips|powerpc|sparc|s390)',
            r'\bin\s+(x86|arm|mips|powerpc|sparc|s390)',
            r'\bfor\s+(x86|arm|mips|powerpc|sparc|s390)',
            # Architecture-specific register or instruction mentions
            r'\b(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp)\b',  # x86_64 registers
            r'\b(eax|ebx|ecx|edx|esi|edi|esp|ebp)\b',  # x86 registers
            r'\b(r0|r1|r2|r3|r4|r5|r6|r7|r8|r9|r10|r11|r12|sp|lr|pc)\b.*arm',  # ARM registers
        ]
        
        import re
        for pattern in explicit_arch_mentions:
            match = re.search(pattern, description, re.IGNORECASE)
            if match:
                mentioned_item = match.group(1) if match.groups() else match.group(0)
                
                # Check if it's compatible with current architecture
                is_compatible = False
                if 'x86' in mentioned_item.lower() and current_arch_normalized in ['x86', 'x86_64']:
                    is_compatible = True
                elif 'arm' in mentioned_item.lower() and current_arch_normalized in ['arm', 'arm64']:
                    is_compatible = True
                elif any(reg in mentioned_item.lower() for reg in ['rax', 'rbx', 'eax', 'ebx']) and current_arch_normalized in ['x86', 'x86_64']:
                    is_compatible = True
                elif 'r0' in mentioned_item.lower() and 'arm' in description and current_arch_normalized in ['arm', 'arm64']:
                    is_compatible = True
                
                if not is_compatible:
                    return {
                        'compatible': False,
                        'reason': f'CVE contains architecture-specific details for different architecture',
                        'detail': f"CVE contains architecture-specific details not compatible with {self.arch}. Architecture is not used."
                    }
        
        # Check patch content for architecture-specific file paths if available
        if patch_content:
            # Look for architecture-specific file paths in patch content
            patch_lines = patch_content.split('\n')
            arch_specific_file_paths = []
            
            for line in patch_lines:
                # Check for file path indicators in patches (diff headers)
                if line.startswith('+++') or line.startswith('---') or line.startswith('diff --git'):
                    # Extract file paths from patch headers
                    for arch, patterns in arch_path_patterns.items():
                        if arch != current_arch_normalized:
                            for pattern in patterns:
                                if pattern.replace('r\'', '').replace('\'', '') in line:
                                    arch_specific_file_paths.append((arch, line.strip()))
                                    break
            
            if arch_specific_file_paths:
                detected_arch = arch_specific_file_paths[0][0]  # Get first detected architecture
                return {
                    'compatible': False,
                    'reason': f'Patch modifies {detected_arch}-specific files but system uses {self.arch}',
                    'detail': f"Patch modifies {detected_arch}-specific files but this system uses {self.arch}. Architecture is not compatible."
                }
        
        # Check patch URLs for architecture-specific patterns if available
        if cve_info and hasattr(cve_info, 'patch_urls') and cve_info.patch_urls:
            for patch_url in cve_info.patch_urls:
                patch_url_lower = patch_url.lower()
                
                # Check for architecture-specific paths in patch URLs
                for arch, patterns in arch_path_patterns.items():
                    if arch != current_arch_normalized:
                        for pattern in patterns:
                            # Remove regex markers for simple string matching in URLs
                            simple_pattern = pattern.replace('r\'', '').replace('\'', '').replace('/', '%2F')
                            if simple_pattern in patch_url_lower or pattern.replace('r\'', '').replace('\'', '') in patch_url_lower:
                                return {
                                    'compatible': False,
                                    'reason': f'Patch URL targets {arch}-specific files but system uses {self.arch}',
                                    'detail': f"Patch targets {arch}-specific files but this system uses {self.arch}. Architecture is not compatible."
                                }
        
        # If we get here, no incompatibility was detected
        return {
            'compatible': True,
            'reason': 'No architecture incompatibility detected',
            'detail': f'CVE appears compatible with {self.arch} architecture'
        }

    @timed_method
    def _process_cve_parallel(self, cve: Dict, kernel_config: List[str], kernel_source_path: str) -> Tuple[str, Optional[VulnerabilityAnalysis]]:
        """Process a single CVE for parallel execution."""
        try:
            check_interrupt()  # Check for interrupt at start of CVE processing
            cve_id = cve.get('id', '')
            analysis = self.check_kernel_config(cve, kernel_config, kernel_source_path)
            return cve_id, analysis
        except KeyboardInterrupt:
            # Re-raise keyboard interrupts to allow graceful shutdown
            raise
        except Exception as e:
            if self.verbose:
                print(f"Error in parallel CVE processing for {cve.get('id', 'unknown')}: {e}")
            # Don't register analysis outcomes for errors - return None
            return cve.get('id', ''), None

    @timed_method
    def _batch_process_vulnerabilities(self, vulnerabilities: List[Dict], kernel_config: List[str], 
                                     kernel_source_path: str, max_workers: Optional[int] = None) -> Dict[str, VulnerabilityAnalysis]:
        """Process multiple vulnerabilities with parallel execution."""
        if not vulnerabilities:
            return {}
        
        check_interrupt()  # Check for interrupt before starting batch
        
        if max_workers is None:
            max_workers = min(self.MAX_PARALLEL_WORKERS, len(vulnerabilities))
        
        results = {}
        total_vulns = len(vulnerabilities)
        completed = 0
        start_time = time.time()
        
        if max_workers == 1 or len(vulnerabilities) == 1:
            # Sequential processing with progress and ETA
            for i, vuln in enumerate(vulnerabilities):
                check_interrupt()  # Check for interrupt before each CVE
                cve_id, analysis = self._process_cve_parallel(vuln, kernel_config, kernel_source_path)
                if cve_id and analysis is not None:  # Only store actual analysis results
                    results[cve_id] = analysis
                
                completed += 1
                progress = (completed / total_vulns) * 100
                
                # Calculate ETA
                elapsed_time = time.time() - start_time
                if completed > 0:
                    avg_time_per_cve = elapsed_time / completed
                    remaining_cves = total_vulns - completed
                    eta_seconds = remaining_cves * avg_time_per_cve
                    eta_str = self._format_eta(eta_seconds) if remaining_cves > 0 else "Done"
                    print(f"\r🔍 Progress: {completed}/{total_vulns} ({progress:.1f}%) - Current: {cve_id} - ETA: {eta_str}", end='', flush=True)
                else:
                    print(f"\r🔍 Progress: {completed}/{total_vulns} ({progress:.1f}%) - Current: {cve_id}", end='', flush=True)
            
            print()  # New line after progress
        else:
            # Parallel processing with progress and ETA
            if self.verbose:
                print(f"Processing {len(vulnerabilities)} vulnerabilities with {max_workers} workers")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all tasks
                future_to_cve = {
                    executor.submit(self._process_cve_parallel, vuln, kernel_config, kernel_source_path): vuln
                    for vuln in vulnerabilities
                }
                
                # Collect results as they complete with progress tracking and ETA
                for future in as_completed(future_to_cve):
                    check_interrupt()  # Check for interrupt while collecting results
                    try:
                        cve_id, analysis = future.result(timeout=300)  # 5 minute timeout per CVE
                        if cve_id and analysis is not None:  # Only store actual analysis results
                            results[cve_id] = analysis
                    except Exception as e:
                        vuln = future_to_cve[future]
                        cve_id = vuln.get('id', 'unknown')
                        if self.verbose:
                            print(f"Parallel processing failed for {cve_id}: {e}")
                        
                        # Don't register analysis outcomes for errors - skip this CVE
                    
                    # Update progress with ETA
                    completed += 1
                    progress = (completed / total_vulns) * 100
                    
                    # Calculate ETA for parallel processing
                    elapsed_time = time.time() - start_time
                    if completed > 0:
                        avg_time_per_cve = elapsed_time / completed
                        remaining_cves = total_vulns - completed
                        eta_seconds = remaining_cves * avg_time_per_cve
                        eta_str = self._format_eta(eta_seconds) if remaining_cves > 0 else "Done"
                        print(f"\r🔍 Progress: {completed}/{total_vulns} ({progress:.1f}%) - Last: {cve_id} - ETA: {eta_str}", end='', flush=True)
                    else:
                        print(f"\r🔍 Progress: {completed}/{total_vulns} ({progress:.1f}%) - Last: {cve_id}", end='', flush=True)
                
                print()  # New line after progress
        
        return results

    @timed_method
    def update_analysis_state(self, vex_data: Dict, kernel_config: List[str], kernel_source_path: str, 
                            reanalyse: bool = False, cve_id: Optional[str] = None, 
                            max_workers: Optional[int] = None) -> Dict:
        """
        Update VEX data with vulnerability analysis results.
        
        Args:
            vex_data: VEX document to update
            kernel_config: List of enabled kernel configuration options
            kernel_source_path: Path to kernel source code
            reanalyse: Force re-analysis of existing results
            cve_id: Analyze only specific CVE (optional)
            max_workers: Number of parallel workers (optional)
        """
        if not vex_data or 'vulnerabilities' not in vex_data:
            raise ValueError("Invalid VEX data: missing vulnerabilities section")
        
        vulnerabilities = vex_data['vulnerabilities']
        
        if cve_id:
            # Filter to specific CVE
            vulnerabilities = [v for v in vulnerabilities if v.get('id') == cve_id]
            if not vulnerabilities:
                raise ValueError(f"CVE {cve_id} not found in VEX data")
        
        # Filter vulnerabilities that need analysis
        to_analyze = []
        for vuln in vulnerabilities:
            cve_vuln_id = vuln.get('id', '')
            
            # Skip if already analyzed and not forcing re-analysis
            if not reanalyse and 'analysis' in vuln:
                existing_state = vuln['analysis'].get('state')
                final_states = {e.value for e in VulnerabilityState if e != VulnerabilityState.IN_TRIAGE}
                if existing_state in final_states:
                    if self.verbose:
                        print(f"Skipping {cve_vuln_id} - already analyzed as {existing_state}")
                    continue
            
            to_analyze.append(vuln)
        
        if not to_analyze:
            if self.verbose:
                print("No vulnerabilities need analysis")
            return vex_data
        
        print(f"📊 Analysis Plan:")
        print(f"   Total vulnerabilities: {len(vulnerabilities)}")
        print(f"   Need analysis: {len(to_analyze)}")
        print(f"   Already analyzed: {len(vulnerabilities) - len(to_analyze)}")
        print()
        
        # Process vulnerabilities (potentially in parallel)
        analysis_results = self._batch_process_vulnerabilities(
            to_analyze, kernel_config, kernel_source_path, max_workers
        )
        
        # Update VEX data with results
        print("📝 Updating VEX data with analysis results...")
        updated_count = 0
        total_to_update = len(analysis_results)
        update_start_time = time.time()
        
        for vuln in vex_data['vulnerabilities']:
            cve_vuln_id = vuln.get('id', '')
            
            if cve_vuln_id in analysis_results:
                analysis = analysis_results[cve_vuln_id]
                
                # Update the vulnerability analysis
                vuln['analysis'] = analysis.to_dict()
                updated_count += 1
                
                if self.verbose:
                    print(f"Updated {cve_vuln_id}: {analysis.state.value}")
                elif total_to_update > 5:  # Show progress for large updates
                    progress = (updated_count / total_to_update) * 100
                    
                    # Calculate ETA for update process
                    elapsed_time = time.time() - update_start_time
                    if updated_count > 0 and updated_count < total_to_update:
                        avg_time_per_update = elapsed_time / updated_count
                        remaining_updates = total_to_update - updated_count
                        eta_seconds = remaining_updates * avg_time_per_update
                        eta_str = self._format_eta(eta_seconds)
                        print(f"\r📝 Updating: {updated_count}/{total_to_update} ({progress:.1f}%) - ETA: {eta_str}", end='', flush=True)
                    else:
                        print(f"\r📝 Updating: {updated_count}/{total_to_update} ({progress:.1f}%)", end='', flush=True)
        
        if total_to_update > 5:
            print()  # New line after progress
        
        print(f"✅ Updated {updated_count} vulnerabilities")
        
        return vex_data

    @staticmethod
    def save_vex_file(vex_data: Dict, file_path: str) -> None:
        """Save VEX data to file with proper formatting."""
        try:
            with open(file_path, 'w') as f:
                json.dump(vex_data, f, indent=2, sort_keys=True)
        except Exception as e:
            raise IOError(f"Failed to save VEX file {file_path}: {e}")

    @timed_method
    def generate_vulnerability_report(self, vex_data: Dict) -> Dict:
        """Generate a comprehensive vulnerability report from VEX data."""
        # Initialize report with all vulnerability states from enum
        report = {}
        
        # Add all state counts
        for state in VulnerabilityState:
            report[state.value] = 0
            
        # Add other fields
        report['total'] = 0
        report['vulnerabilities'] = {}
        report['summary'] = {}
        report['timestamp'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        if 'vulnerabilities' not in vex_data:
            return report
        
        vulnerabilities = vex_data['vulnerabilities']
        report['total'] = len(vulnerabilities)
        
        # Categorize vulnerabilities
        by_state = {}
        by_severity = {}
        
        for vuln in vulnerabilities:
            cve_id = vuln.get('id', 'unknown')
            analysis = vuln.get('analysis', {})
            state = analysis.get('state', VulnerabilityState.IN_TRIAGE.value)
            
            # Count by state using CycloneDX v1.6 states
            try:
                # Validate that the state is a valid enum value
                valid_state = VulnerabilityState(state)
                report[valid_state.value] += 1
            except ValueError:
                # Default unknown states to in_triage
                report[VulnerabilityState.IN_TRIAGE.value] += 1
                state = VulnerabilityState.IN_TRIAGE.value
            
            # Store vulnerability details
            vuln_details = {
                'state': state,
                'justification': analysis.get('justification'),
                'detail': analysis.get('detail'),
                'timestamp': analysis.get('timestamp')
            }
            
            # Add severity if available
            severity = analysis.get('severity')
            if severity:
                vuln_details['severity'] = severity
                by_severity[severity] = by_severity.get(severity, 0) + 1
            
            report['vulnerabilities'][cve_id] = vuln_details
            by_state[state] = by_state.get(state, 0) + 1
        
        # Add summary statistics
        report['summary'] = {
            'by_state': by_state,
            'by_severity': by_severity,
            'completion_rate': (
                (report[VulnerabilityState.RESOLVED.value] + report[VulnerabilityState.RESOLVED_WITH_PEDIGREE.value] + 
                 report[VulnerabilityState.EXPLOITABLE.value] + report[VulnerabilityState.FALSE_POSITIVE.value] + 
                 report[VulnerabilityState.NOT_AFFECTED.value]) / report['total'] * 100
                if report['total'] > 0 else 0
            )
        }
        
        return report

    def validate_vex_data(self, vex_data: Dict) -> List[str]:
        """Validate VEX data structure and return list of issues."""
        issues = []
        
        # Check required fields
        if not isinstance(vex_data, dict):
            issues.append("VEX data must be a dictionary")
            return issues
        
        if 'vulnerabilities' not in vex_data:
            issues.append("Missing 'vulnerabilities' section")
            return issues
        
        vulnerabilities = vex_data['vulnerabilities']
        if not isinstance(vulnerabilities, list):
            issues.append("'vulnerabilities' must be a list")
            return issues
        
        if not vulnerabilities:
            issues.append("No vulnerabilities found in VEX data")
            return issues
        
        # Validate each vulnerability
        for i, vuln in enumerate(vulnerabilities):
            vuln_prefix = f"Vulnerability {i+1}"
            
            if not isinstance(vuln, dict):
                issues.append(f"{vuln_prefix}: must be a dictionary")
                continue
            
            # Check required fields
            if 'id' not in vuln:
                issues.append(f"{vuln_prefix}: missing 'id' field")
            else:
                cve_id = vuln['id']
                if not cve_id or not isinstance(cve_id, str):
                    issues.append(f"{vuln_prefix}: 'id' must be a non-empty string")
                elif not cve_id.startswith('CVE-'):
                    issues.append(f"{vuln_prefix}: 'id' should start with 'CVE-'")
            
            # Validate analysis section if present
            if 'analysis' in vuln:
                analysis = vuln['analysis']
                if not isinstance(analysis, dict):
                    issues.append(f"{vuln_prefix}: 'analysis' must be a dictionary")
                else:
                    if 'state' in analysis:
                        state = analysis['state']
                        # Use enum values for validation
                        valid_states = [s.value for s in VulnerabilityState]
                        if state not in valid_states:
                            issues.append(f"{vuln_prefix}: invalid state '{state}', must be one of {valid_states}")
                    
                    if 'justification' in analysis:
                        justification = analysis['justification']
                        if justification is not None:  # Allow None values
                            # Check if justification is incorrectly formatted as a list
                            if isinstance(justification, list):
                                if len(justification) == 1:
                                    issues.append(f"{vuln_prefix}: justification should be a string, not an array. Use '{justification[0]}' instead of {justification}")
                                else:
                                    issues.append(f"{vuln_prefix}: justification should be a single string, not an array {justification}")
                            else:
                                valid_justifications = [j.value for j in Justification]
                                if justification not in valid_justifications:
                                    issues.append(f"{vuln_prefix}: invalid justification '{justification}', must be one of {valid_justifications}")
                    
                    if 'response' in analysis:
                        response = analysis['response']
                        if response is not None:  # Allow None values
                            # Check if response is incorrectly formatted as a list
                            if isinstance(response, list):
                                if len(response) == 1:
                                    issues.append(f"{vuln_prefix}: response should be a string, not an array. Use '{response[0]}' instead of {response}")
                                else:
                                    issues.append(f"{vuln_prefix}: response should be a single string, not an array {response}")
                            else:
                                valid_responses = [r.value for r in Response]
                                if response not in valid_responses:
                                    issues.append(f"{vuln_prefix}: invalid response '{response}', must be one of {valid_responses}")
        
        return issues

    def print_vulnerability_summary(self, report: Dict) -> None:
        """Print a formatted vulnerability summary report."""
        print("\n" + "="*60)
        print("VULNERABILITY ANALYSIS SUMMARY")
        print("="*60)
        
        total = report.get('total', 0)
        resolved = report.get(VulnerabilityState.RESOLVED.value, 0)
        resolved_with_pedigree = report.get(VulnerabilityState.RESOLVED_WITH_PEDIGREE.value, 0)
        exploitable = report.get(VulnerabilityState.EXPLOITABLE.value, 0)
        in_triage = report.get(VulnerabilityState.IN_TRIAGE.value, 0)
        false_positive = report.get(VulnerabilityState.FALSE_POSITIVE.value, 0)
        not_affected = report.get(VulnerabilityState.NOT_AFFECTED.value, 0)
        
        print(f"Total vulnerabilities analyzed: {total}")
        print(f"├─ ✅ Not affected: {not_affected}")
        print(f"├─ 🔧 Resolved: {resolved}")
        print(f"├─ 🔧📋 Resolved with pedigree: {resolved_with_pedigree}")
        print(f"├─ ⚠️  Exploitable: {exploitable}")
        print(f"├─ ❌ False positive: {false_positive}")
        print(f"└─ 🔍 In triage: {in_triage}")
        
        if total > 0:
            completion_rate = ((resolved + resolved_with_pedigree + exploitable + false_positive + not_affected) / total) * 100
            print(f"\nAnalysis completion rate: {completion_rate:.1f}%")
        
        # Show severity breakdown if available
        summary = report.get('summary', {})
        by_severity = summary.get('by_severity', {})
        if by_severity:
            print(f"\nSeverity breakdown:")
            for severity, count in sorted(by_severity.items()):
                print(f"  {severity}: {count}")
        
        # Show exploitable vulnerabilities if any
        if exploitable > 0:
            print(f"\n⚠️  EXPLOITABLE VULNERABILITIES:")
            vulnerabilities = report.get('vulnerabilities', {})
            exploitable_list = [
                cve_id for cve_id, details in vulnerabilities.items() 
                if details.get('state') == VulnerabilityState.EXPLOITABLE.value
            ]
            for cve_id in sorted(exploitable_list[:10]):  # Show first 10
                vuln_details = vulnerabilities[cve_id]
                detail = vuln_details.get('detail', 'No details available')
                print(f"  • {cve_id}: {detail}")
            
            if len(exploitable_list) > 10:
                print(f"  ... and {len(exploitable_list) - 10} more")
        
        print("="*60)

    def test_webdriver_functionality(self) -> bool:
        """Test WebDriver functionality for patch fetching."""
        if not SELENIUM_AVAILABLE:
            print("❌ Selenium not available")
            return False
        
        if not self.edge_driver_path:
            print("❌ Edge driver path not configured")
            return False
        
        if not os.path.exists(self.edge_driver_path):
            print(f"❌ Edge driver not found: {self.edge_driver_path}")
            return False
        
        try:
            if self.verbose:
                print("Testing WebDriver functionality...")
            
            # Import here to avoid issues when Selenium is not available
            from selenium import webdriver
            from selenium.webdriver.edge.service import Service
            
            service = Service(self.edge_driver_path)
            options = webdriver.EdgeOptions()
            options.add_argument('--headless')
            options.add_argument('--disable-gpu')
            options.add_argument('--no-sandbox')
            
            driver = webdriver.Edge(service=service, options=options)
            driver.set_page_load_timeout(10)
            
            # Test with a simple page
            driver.get("https://httpbin.org/html")
            
            # Check if we can find elements
            page_source = driver.page_source
            success = bool(page_source and len(page_source) > 100)
            
            driver.quit()
            
            if success:
                print("✅ WebDriver functionality test passed")
                return True
            else:
                print("❌ WebDriver test failed - no content retrieved")
                return False
                
        except Exception as e:
            print(f"❌ WebDriver test failed: {e}")
            return False

    def print_performance_stats(self):
        """Print performance statistics."""
        print("\n" + "="*60)
        print("PERFORMANCE STATISTICS")
        print("="*60)
        
        # Print performance tracker summary
        perf_tracker.print_summary()
        
        # Print cache statistics
        print(f"CVEs processed: {len(self._processed_cves)}")
        
        # Print cache sizes
        print(f"\nCache sizes:")
        print(f"  Makefile cache: {len(self._makefile_cache)}")
        print(f"  Config cache: {len(self._config_cache)}")
        print(f"  Source analysis cache: {len(self._source_analysis_cache)}")
        print(f"  File content cache: {len(self._file_content_cache)}")
        
        print("="*60)

    @timed_method
    def _advanced_config_search(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Advanced configuration search using multiple strategies."""
        config_options = set()
        
        # Strategy 1: Source file analysis
        source_configs = self._analyze_source_file_config_hints(source_file_path)
        config_options.update(source_configs)
        
        # Strategy 2: Path-based inference
        path_configs = self._infer_config_from_path(source_file_path, kernel_source_path)
        config_options.update(path_configs)
        
        # Strategy 3: Comprehensive Makefile search
        comprehensive_configs = self._search_all_makefiles(source_file_path, kernel_source_path)
        config_options.update(comprehensive_configs)
        
        return config_options

    @timed_method
    def _search_all_makefiles(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Search all relevant Makefiles using optimized patterns."""
        config_options = set()
        
        # Get directory of source file relative to kernel source
        try:
            rel_path = os.path.relpath(source_file_path, kernel_source_path)
            search_dirs = []
            
            # Add directories to search
            path_parts = rel_path.split(os.sep)
            for i in range(len(path_parts)):
                partial_path = os.path.join(kernel_source_path, *path_parts[:i+1])
                if os.path.isdir(partial_path):
                    search_dirs.append(partial_path)
                else:
                    # Try parent directory
                    parent_dir = os.path.dirname(partial_path)
                    if os.path.isdir(parent_dir):
                        search_dirs.append(parent_dir)
                        break
            
            # Search common kernel directories
            common_dirs = ['drivers', 'net', 'fs', 'arch', 'sound', 'crypto']
            for common_dir in common_dirs:
                common_path = os.path.join(kernel_source_path, common_dir)
                if os.path.isdir(common_path) and any(part in rel_path for part in [common_dir]):
                    search_dirs.append(common_path)
            
            # Process directories by priority
            processed_dirs = set()
            for search_dir in search_dirs[:10]:  # Limit to top 10 directories
                if search_dir not in processed_dirs:
                    processed_dirs.add(search_dir)
                    self._analyze_related_makefiles(search_dir, source_file_path, kernel_source_path, config_options)
                    
        except Exception as e:
            if self.verbose:
                print(f"Error in comprehensive makefile search: {e}")
        
        return config_options

    @timed_method
    def _analyze_source_file_config_hints(self, source_file_path: str) -> Set[str]:
        """
        Look for #ifdef CONFIG_* patterns and other hints in the source code.
        """
        config_options = set()
        
        # Check cache first
        if source_file_path in self._source_analysis_cache:
            self._cache_hits['source'] += 1
            return self._source_analysis_cache[source_file_path]
        
        self._cache_misses['source'] += 1
        
        try:
            # Check if file exists in kernel source
            if not os.path.exists(source_file_path):
                return config_options
            
            content = self._get_cached_file_content(source_file_path)
            
            # Use compiled patterns for performance
            ifdef_pattern = self._patch_patterns[1]  # #ifdef pattern
            if_defined_pattern = self._patch_patterns[2]  # #if defined pattern  
            is_enabled_pattern = self._patch_patterns[3]  # IS_ENABLED pattern
            
            for pattern in [ifdef_pattern, if_defined_pattern, is_enabled_pattern]:
                matches = pattern.findall(content)
                for match in matches:
                    if isinstance(match, tuple):
                        config_option = match[0] if match else ""
                    else:
                        config_option = match
                    
                    if config_option and config_option.startswith('CONFIG_'):
                        config_options.add(config_option)
            
            # Cache the result
            self._source_analysis_cache[source_file_path] = config_options
            
        except Exception as e:
            if self.verbose:
                print(f"Error analyzing source file {source_file_path}: {e}")
        
        return config_options

    @timed_method
    def _infer_config_from_path(self, source_file_path: str, kernel_source_path: str) -> Set[str]:
        """Infer likely configuration options from source file path."""
        config_options = set()
        
        try:
            # Get relative path within kernel source
            rel_path = os.path.relpath(source_file_path, kernel_source_path)
            path_parts = rel_path.split(os.sep)
            
            # Common path-to-config mappings
            path_mappings = {
                'drivers/net': ['CONFIG_NET', 'CONFIG_NETDEVICES'],
                'drivers/bluetooth': ['CONFIG_BT'],
                'drivers/wireless': ['CONFIG_WIRELESS', 'CONFIG_WLAN'],
                'drivers/usb': ['CONFIG_USB'],
                'drivers/pci': ['CONFIG_PCI'],
                'net/': ['CONFIG_NET'],
                'fs/': ['CONFIG_FS'],
                'sound/': ['CONFIG_SOUND', 'CONFIG_SND'],
                'crypto/': ['CONFIG_CRYPTO'],
                'security/': ['CONFIG_SECURITY'],
                'arch/arm64': ['CONFIG_ARM64'],
                'arch/x86': ['CONFIG_X86'],
                'drivers/gpu': ['CONFIG_DRM'],
                'drivers/media': ['CONFIG_MEDIA'],
                'drivers/staging': ['CONFIG_STAGING'],
            }
            
            # Check path mappings
            for path_pattern, configs in path_mappings.items():
                if path_pattern in rel_path:
                    config_options.update(configs)
                    if self.verbose:
                        print(f"Path pattern match: {path_pattern} - adding configs: {', '.join(configs)}")
        
            # Generate CONFIG options from directory names
            for part in path_parts:
                if part and part != '.':
                    # Convert directory name to config option format
                    config_name = f"CONFIG_{part.upper().replace('-', '_').replace('.', '_')}"
                    if re.match(r'CONFIG_[A-Z0-9_]+$', config_name):
                        config_options.add(config_name)
        
            # Special handling for known subsystems
            if 'bluetooth' in rel_path.lower():
                config_options.update(['CONFIG_BT', 'CONFIG_BT_BREDR'])
            if 'wireless' in rel_path.lower() or 'wifi' in rel_path.lower():
                config_options.update(['CONFIG_WIRELESS', 'CONFIG_WLAN'])
            if 'ethernet' in rel_path.lower():
                config_options.update(['CONFIG_NET', 'CONFIG_ETHERNET'])
                
        except Exception as e:
            if self.verbose:
                print(f"Error inferring config from path {source_file_path}: {e}")
        
        return config_options

    @timed_method  
    def in_kernel_config(self, config_options: Set[str], kernel_config: List[str]) -> VulnerabilityAnalysis:
        """Check if configuration options are enabled in kernel config."""
        # Include architecture-specific configs from detected architecture
        all_config_options = set(config_options)
        arch_configs = self.get_arch_specific_configs()
        if arch_configs:
            all_config_options.update(arch_configs)
            if self.verbose and arch_configs:
                print(f"Added architecture-specific configs: {', '.join(arch_configs)}")
        
        if not all_config_options:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.IN_TRIAGE,
                justification=Justification.CODE_NOT_PRESENT,
                response=Response.CAN_NOT_FIX,
                detail="No configuration options found - manual review needed",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        # Check if using only default enabled options
        if all_config_options <= self.ENABLED_DEFAULT_OPTIONS:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.EXPLOITABLE,
                justification=Justification.REQUIRES_CONFIGURATION,
                response=Response.UPDATE,
                detail=f"Uses default enabled options: {', '.join(all_config_options)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        
        # Check each config option
        enabled_configs = set()
        disabled_configs = set()
        
        for config in all_config_options:
            if any(config in line for line in kernel_config):
                enabled_configs.add(config)
            else:
                disabled_configs.add(config)
        
        # Prioritize driver-specific configurations over general ones
        # Identify critical driver-specific configs
        critical_driver_configs = set()
        general_configs = {'CONFIG_NET', 'CONFIG_ETHERNET', 'CONFIG_NETDEVICES', 'CONFIG_USB', 'CONFIG_PCI', 
                          'CONFIG_BLOCK', 'CONFIG_SCSI', 'CONFIG_SOUND', 'CONFIG_INPUT', 'CONFIG_HID',
                          'CONFIG_I2C', 'CONFIG_SPI', 'CONFIG_GPIO', 'CONFIG_DMA_ENGINE', 'CONFIG_OF',
                          'CONFIG_REGMAP', 'CONFIG_IRQ_DOMAIN', 'CONFIG_PINCTRL', 'CONFIG_CLK',
                          'CONFIG_RESET_CONTROLLER', 'CONFIG_RFS_ACCEL', 'CONFIG_CORE'}
        
        # Add architecture configs to general configs so they're not treated as critical
        arch_general_configs = {
            'CONFIG_ARM64', 'CONFIG_ARM64_4K_PAGES', 'CONFIG_ARM64_VA_BITS_48', 'CONFIG_ARM64_64K_PAGES',
            'CONFIG_ARM', 'CONFIG_ARM_THUMB', 'CONFIG_ARM_LPAE',
            'CONFIG_X86', 'CONFIG_X86_64', 'CONFIG_X86_32', 'CONFIG_64BIT',
            'CONFIG_MIPS', 'CONFIG_MIPS32_R1', 'CONFIG_MIPS64',
            'CONFIG_PPC', 'CONFIG_POWERPC', 'CONFIG_PPC64',
            'CONFIG_RISCV', 'CONFIG_RISCV_ISA_C',
            'CONFIG_S390', 'CONFIG_S390X',
            'CONFIG_SPARC', 'CONFIG_SPARC64'
        }
        general_configs.update(arch_general_configs)
        
        for config in all_config_options:
            if config not in general_configs and not config.endswith('_C'):  # Filter out generic file-based configs
                critical_driver_configs.add(config)
        
        # Check critical driver configs first
        enabled_critical = enabled_configs & critical_driver_configs
        disabled_critical = disabled_configs & critical_driver_configs
        
        # Determine vulnerability state based on critical configs
        if enabled_critical:
            # Critical driver configs are enabled - system is vulnerable
            detail_parts = []
            if enabled_critical & config_options:
                detail_parts.append(f"Enabled critical configs: {', '.join(enabled_critical & config_options)}")
            if enabled_critical & arch_configs:
                detail_parts.append(f"Architecture ({self.arch}): {', '.join(enabled_critical & arch_configs)}")
            
            return VulnerabilityAnalysis(
                state=VulnerabilityState.EXPLOITABLE,
                justification=Justification.REQUIRES_CONFIGURATION,
                response=Response.UPDATE,
                detail="; ".join(detail_parts),
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        elif disabled_critical:
            # Critical driver configs are disabled - system is not affected
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.REQUIRES_CONFIGURATION,
                response=Response.WILL_NOT_FIX,
                detail=f"Required driver configs not enabled: {', '.join(disabled_critical)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        elif enabled_configs:
            # Only general configs enabled - likely not affected but needs review
            return VulnerabilityAnalysis(
                state=VulnerabilityState.IN_TRIAGE,
                justification=Justification.REQUIRES_CONFIGURATION,
                response=Response.CAN_NOT_FIX,
                detail=f"Only general configs enabled, no specific driver configs found: {', '.join(enabled_configs)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )
        else:
            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.CODE_NOT_PRESENT,
                response=Response.WILL_NOT_FIX,
                detail=f"Required configs not enabled: {', '.join(disabled_configs)}",
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            )

    @staticmethod
    def extract_arch_from_config(kernel_config: List[str]) -> Tuple[Optional[str], Optional[str]]:
        """Extract architecture information from kernel configuration."""
        # Architecture config mappings - order matters, check specific configs first
        arch_config_mappings = [
            # Check 64-bit variants first
            ('CONFIG_X86_64', ('x86_64', 'CONFIG_X86_64')),
            ('CONFIG_SPARC64', ('sparc64', 'CONFIG_SPARC64')),
            # Then check main architecture configs
            ('CONFIG_ARM64', ('arm64', 'CONFIG_ARM64')),
            ('CONFIG_ARM', ('arm', 'CONFIG_ARM')),
            ('CONFIG_X86', ('x86', 'CONFIG_X86')),
            ('CONFIG_MIPS', ('mips', 'CONFIG_MIPS')),
            ('CONFIG_POWERPC', ('powerpc', 'CONFIG_POWERPC')),
            ('CONFIG_PPC', ('powerpc', 'CONFIG_PPC')),
            ('CONFIG_RISCV', ('riscv', 'CONFIG_RISCV')),
            ('CONFIG_S390', ('s390', 'CONFIG_S390')),
            ('CONFIG_SPARC', ('sparc', 'CONFIG_SPARC')),
            ('CONFIG_ALPHA', ('alpha', 'CONFIG_ALPHA')),
            ('CONFIG_IA64', ('ia64', 'CONFIG_IA64')),
            ('CONFIG_M68K', ('m68k', 'CONFIG_M68K')),
            ('CONFIG_MICROBLAZE', ('microblaze', 'CONFIG_MICROBLAZE')),
            ('CONFIG_PARISC', ('parisc', 'CONFIG_PARISC')),
            ('CONFIG_SH', ('sh', 'CONFIG_SH')),
            ('CONFIG_UML', ('um', 'CONFIG_UML')),
            ('CONFIG_XTENSA', ('xtensa', 'CONFIG_XTENSA')),
        ]
        
        # Check for exact architecture config options in order of specificity
        for config_option in kernel_config:
            for arch_config, (arch, arch_config_name) in arch_config_mappings:
                if config_option == arch_config:
                    return arch, arch_config_name
                
        # If no explicit architecture config found, try to infer from sub-arch configs
        for config_option in kernel_config:
            # ARM64 specific configs
            if config_option.startswith('CONFIG_ARM64_'):
                return 'arm64', 'CONFIG_ARM64'
            # ARM specific configs  
            elif config_option.startswith('CONFIG_ARM_'):
                return 'arm', 'CONFIG_ARM'
            # x86 specific configs
            elif config_option.startswith('CONFIG_X86_') and config_option != 'CONFIG_X86_64':
                return 'x86', 'CONFIG_X86'
            # MIPS specific configs
            elif config_option.startswith('CONFIG_MIPS_'):
                return 'mips', 'CONFIG_MIPS'
            # PowerPC specific configs
            elif config_option.startswith('CONFIG_PPC_') or config_option.startswith('CONFIG_POWERPC_'):
                return 'powerpc', 'CONFIG_POWERPC'
            # RISCV specific configs
            elif config_option.startswith('CONFIG_RISCV_'):
                return 'riscv', 'CONFIG_RISCV'
        
        return None, None

    @staticmethod
    def extract_arch_info(path: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract architecture information from file path (legacy method)."""
        arch_patterns = {
            'x86': r'arch/x86/',
            'arm64': r'arch/arm64/',
            'arm': r'arch/arm/',
            'mips': r'arch/mips/',
            'powerpc': r'arch/powerpc/',
            'riscv': r'arch/riscv/',
            's390': r'arch/s390/',
            'sparc': r'arch/sparc/',
        }
        
        for arch, pattern in arch_patterns.items():
            if re.search(pattern, path):
                # Special mapping for architectures
                if arch == 'arm':
                    return arch, "CONFIG_ARM"
                elif arch == 'arm64':
                    return arch, "CONFIG_ARM64"
                else:
                    return arch, f"CONFIG_{arch.upper()}"
        
        return None, None

    def _filter_relevant_config_options(self, config_options: Set[str]) -> Set[str]:
        """Filter out build-time, debug, and irrelevant configuration options."""
        filtered_configs = set()
        
        # Options to filter out (build-time, debug, experimental, etc.)
        filter_patterns = [
            # Build and compile time options
            'CC_HAS_', 'GCC_PLUGIN_', 'LTO_', 'CFI_', 'CLANG_',
            'COMPILE_', 'BUILD_', '_BUILD', 'HEADERS_INSTALL',
            'STRIP_ASM_SYMS', 'FRAME_WARN', 'MCOUNT',
            
            # Debug and tracing options
            'DEBUG_', 'FTRACE_', 'FUNCTION_GRAPH_TRACER',
            'DEBUG_INFO_BTF', 'STACK_VALIDATION',
            
            # Expert/experimental options
            'EXPERT', 'EXPERIMENTAL', 'BROKEN',
            
            # Test options
            'KUNIT', 'SELFTEST', 'TEST_',
            
            # Architecture specific that are usually not relevant for CVE analysis
            'SUPERH', 'UML', 'ARCH_SUPPORTS_',
            
            # Performance optimization flags
            'OPTIMIZE_FOR_', 'SHADOW_CALL_STACK', 'RETHUNK',
            
            # Init options that don't affect runtime
            'INIT_STACK_', 'AUTO_VAR_INIT_'
        ]
        
        for config in config_options:
            # Keep config if it doesn't match any filter pattern
            if not any(pattern in config for pattern in filter_patterns):
                filtered_configs.add(config)
        
        return filtered_configs

    def get_arch_specific_configs(self) -> Set[str]:
        """Get architecture-specific configuration options from detected architecture."""
        arch_configs = set()
        
        if self.arch and self.arch_config:
            arch_configs.add(self.arch_config)
            
            # Add common architecture-specific configs
            arch_specific_mappings = {
                'arm': ['CONFIG_ARM', 'CONFIG_ARM_THUMB', 'CONFIG_ARM_LPAE'],
                'arm64': ['CONFIG_ARM64', 'CONFIG_ARM64_4K_PAGES', 'CONFIG_ARM64_VA_BITS_48'],
                'x86': ['CONFIG_X86', 'CONFIG_X86_32'],
                'x86_64': ['CONFIG_X86', 'CONFIG_X86_64', 'CONFIG_64BIT'],
                'mips': ['CONFIG_MIPS', 'CONFIG_MIPS32_R1'],
                'powerpc': ['CONFIG_PPC', 'CONFIG_POWERPC'],
                'riscv': ['CONFIG_RISCV'],
                's390': ['CONFIG_S390'],
                'sparc': ['CONFIG_SPARC'],
                'sparc64': ['CONFIG_SPARC64', '64BIT']
            }
            
            if self.arch in arch_specific_mappings:
                arch_configs.update(arch_specific_mappings[self.arch])
        
        return arch_configs
    
    def is_arch_compatible_cve(self, cve: Dict, source_file_path: Optional[str] = None) -> bool:
        """
        Check if a CVE is compatible with the detected architecture.
        Returns True if architecture is compatible or cannot be determined.
        """
        if not self.arch:
            # If no architecture detected, assume compatible
            return True
            
        # Check source file path for architecture-specific paths
        if source_file_path:
            # Extract architecture from path
            path_arch, _ = self.extract_arch_info(source_file_path)
            if path_arch and path_arch != self.arch:
                if self.verbose:
                    print(f"Architecture mismatch: detected {self.arch}, CVE affects {path_arch}")
                return False
        
        # Check CVE description for architecture mentions
        description = cve.get('description', '').lower()
        
        # Architecture keywords that would make CVE incompatible
        incompatible_arch_keywords = {
            'arm': ['x86', 'amd64', 'intel', 'mips', 'powerpc', 'sparc', 's390'],
            'arm64': ['x86', 'amd64', 'intel', 'mips', 'powerpc', 'sparc', 's390', 'arm32'],
            'x86': ['arm', 'aarch64', 'mips', 'powerpc', 'sparc', 's390'],
            'x86_64': ['arm', 'aarch64', 'mips', 'powerpc', 'sparc', 's390', 'i386'],
            'mips': ['arm', 'aarch64', 'x86', 'amd64', 'intel', 'powerpc', 'sparc', 's390'],
            'powerpc': ['arm', 'aarch64', 'x86', 'amd64', 'intel', 'mips', 'sparc', 's390'],
            'riscv': ['arm', 'aarch64', 'x86', 'amd64', 'intel', 'mips', 'powerpc', 'sparc', 's390'],
            's390': ['arm', 'aarch64', 'x86', 'amd64', 'intel', 'mips', 'powerpc', 'sparc'],
            'sparc': ['arm', 'aarch64', 'x86', 'amd64', 'intel', 'mips', 'powerpc', 's390']
        }
        
        if self.arch in incompatible_arch_keywords:
            for incompatible_keyword in incompatible_arch_keywords[self.arch]:
                if incompatible_keyword in description:
                    if self.verbose:
                        print(f"CVE description mentions incompatible architecture: {incompatible_keyword}")
                    return False
        
        return True
        

def main():
    """Main entry point for the VEX Kernel Checker."""
    
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
    parser.add_argument('--detailed-timing', action='store_true', help='Show detailed method timing (verbose performance output)')
    
    args = parser.parse_args()
    
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
    
    # Set output file
    output_file = args.output if args.output else args.vex_file
    
    try:
        # Load VEX data
        perf_tracker.start_timer('load_vex_data')
        print(f"Loading VEX data from {args.vex_file}...")
        vex_data = VexKernelChecker.load_vex_file(args.vex_file)
        perf_tracker.end_timer('load_vex_data')
        
        # Load kernel config
        perf_tracker.start_timer('load_kernel_config')
        print(f"Loading kernel configuration from {args.kernel_config}...")
        kernel_config = VexKernelChecker.load_kernel_config(args.kernel_config)
        perf_tracker.end_timer('load_kernel_config')
        
        print(f"Loaded {len(kernel_config)} configuration options")
        
        # Extract architecture from kernel configuration
        perf_tracker.start_timer('extract_architecture')
        arch, arch_config = VexKernelChecker.extract_arch_from_config(kernel_config)
        perf_tracker.end_timer('extract_architecture')
        
        if arch and arch_config:
            print(f"Detected architecture: {arch} ({arch_config})")
        else:
            print("Warning: Could not detect architecture from kernel configuration")
            print("This may affect the accuracy of vulnerability analysis")
        
        
        # Initialize checker
        # Only disable patch checking if explicitly requested with --config-only
        # NVD API doesn't require an API key (API key just provides higher rate limits)
        disable_patch_checking = args.config_only
        
        print(f"Initializing VEX Kernel Checker...")
        checker = VexKernelChecker(
            verbose=args.verbose,
            api_key=args.api_key,
            edge_driver_path=args.edge_driver,
            disable_patch_checking=disable_patch_checking,
            analyze_all_cves=args.analyze_all_cves,
            arch=arch,
            arch_config=arch_config,
            detailed_timing=args.detailed_timing
        )
        
        # Clear cache if requested
        if args.clear_cache:
            print("Clearing caches...")
            checker.clear_all_caches()
        
        # Validate VEX data
        validation_issues = checker.validate_vex_data(vex_data)
        if validation_issues:
            print(f"VEX data validation warnings:")
            for issue in validation_issues[:3]:
                print(f"  ⚠️  {issue}")
            if len(validation_issues) > 3:
                print(f"  ... and {len(validation_issues) - 3} more issues")
            print()
        
        # Perform analysis
        print("\n" + "="*60)
        print("🚀 STARTING VULNERABILITY ANALYSIS")
        print("="*60)
        
        # Show analysis overview
        total_vulns = len(vex_data.get('vulnerabilities', []))
        print(f"📋 Analysis Overview:")
        print(f"   Total vulnerabilities: {total_vulns}")
        print(f"   Kernel configuration: {len(kernel_config)} options")
        print(f"   Architecture: {arch if arch else 'Unknown'}")
        print(f"   Patch checking: {'Enabled' if not disable_patch_checking else 'Disabled'}")
        print(f"   API key: {'Provided' if args.api_key else 'Not provided (rate limited)'}")
        print()
        
        start_time = time.time()
        
        updated_vex_data = checker.update_analysis_state(
            vex_data=vex_data,
            kernel_config=kernel_config,
            kernel_source_path=args.kernel_source,
            reanalyse=args.reanalyse,
            cve_id=args.cve_id
        )
        
        analysis_time = time.time() - start_time
        print("\n" + "="*60)
        print("✅ ANALYSIS COMPLETED")
        print("="*60)
        print(f"⏱️  Total analysis time: {analysis_time:.2f} seconds")
        print(f"📊 Performance: {total_vulns / analysis_time:.1f} CVEs/second" if analysis_time > 0 else "")
        print()
        
        # Generate report
        report = checker.generate_vulnerability_report(updated_vex_data)
        checker.print_vulnerability_summary(report)
        
        # Save results
        print(f"\n💾 Saving results to {output_file}...")
        VexKernelChecker.save_vex_file(updated_vex_data, output_file)
        print(f"✅ Results saved to {output_file}")
        
        # Performance stats
        if args.performance_stats:
            checker.print_performance_stats()
        
        # Final summary
        exploitable_count = report.get('exploitable', 0)
        not_affected_count = report.get('not_affected', 0)
        in_triage_count = report.get('in_triage', 0)
        resolved_count = report.get('resolved', 0)
        resolved_with_pedigree_count = report.get('resolved_with_pedigree', 0)
        false_positive_count = report.get('false_positive', 0)
        
        print(f"\n🎯 Final Summary:")
        print(f"   ✅ Not affected: {not_affected_count}")
        print(f"   🔧 Resolved: {resolved_count}")
        print(f"   🔧📋 Resolved with pedigree: {resolved_with_pedigree_count}")
        print(f"   ⚠️  Exploitable: {exploitable_count}")
        print(f"   ❌ False positive: {false_positive_count}")
        print(f"   🔍 In triage: {in_triage_count}")
        
        if exploitable_count > 0:
            print(f"\n⚠️  Warning: {exploitable_count} vulnerabilities may affect this kernel")
            print("   Review analysis details and consider patches or config changes")
        
        if in_triage_count > 0:
            print(f"\n🔍 Note: {in_triage_count} vulnerabilities need manual review")
            
        return 0
            
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 1
    except Exception as e:
        print(f"Error during analysis: {e}")
        if args.verbose:
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())
