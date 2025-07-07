"""
Base class for VEX Kernel Checker with common functionality.
"""

import json
import os
import re
import time
from typing import Dict, List, Optional, Tuple

from .common import PerformanceTracker, timed_method


class VexKernelCheckerBase:
    """Base class with common functionality for VEX Kernel Checker components."""

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
        'https://codereview.qt-project.org',
        'https://github.com/qt',
        'https://www.qt.io/',
    }

    ENABLED_DEFAULT_OPTIONS = {
        'CONFIG_NET',
        'CONFIG_BT',
        'CONFIG_GENERIC_PHY',
        'CONFIG_SND_SOC',
    }

    PATH_REPLACEMENTS = {
        'b//': "",
        'smb/client': 'cifs',
        'smb/server': 'ksmbd',
        'net/wireless/silabs': 'staging',
    }

    # Performance optimization flags
    ENABLE_AGGRESSIVE_CACHING = True
    ENABLE_PARALLEL_FILE_IO = True
    ENABLE_SMART_SEARCH_ORDERING = True

    def __init__(
        self,
        verbose: bool = False,
        detailed_timing: bool = False,
        check_patches: bool = False,
        analyze_all_cves: bool = False,
        arch: Optional[str] = None,
        api_key: Optional[str] = None,
        edge_driver_path: Optional[str] = None,
        **kwargs,
    ):
        """
        Initialize the base checker.

        Args:
            verbose: Enable verbose output
            detailed_timing: Enable detailed timing output
            check_patches: Enable patch fetching and analysis
            analyze_all_cves: Analyze all CVEs regardless of kernel relation
            arch: System architecture (auto-detected if None)
            api_key: NVD API key for CVE details
            edge_driver_path: Path to Edge WebDriver executable
            **kwargs: Additional arguments (ignored for flexibility)
        """
        self.verbose = verbose
        self.detailed_timing = detailed_timing
        self.check_patches = check_patches
        self.analyze_all_cves = analyze_all_cves
        self.arch = arch or self._detect_architecture()
        self.api_key = api_key
        self.edge_driver_path = edge_driver_path

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

        # Performance tracker
        self.perf_tracker = PerformanceTracker()

    @timed_method
    def _get_cached_file_content(self, file_path: str) -> str:
        """Get file content with caching."""
        if file_path in self._file_content_cache:
            self._record_cache_hit('file_content')
            return self._file_content_cache[file_path]

        self._record_cache_miss('file_content')
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
                print(f'Error reading file {file_path}: {e}')
            return ""

    @timed_method
    def _get_cached_makefile_vars(self, makefile_path: str) -> Dict[str, str]:
        """Get makefile variables with caching."""
        if makefile_path in self._makefile_cache:
            self._record_cache_hit('makefile')
            return self._makefile_cache[makefile_path]

        self._record_cache_miss('makefile')
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
                print(f'Error parsing makefile {makefile_path}: {e}')

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
            print('All caches cleared')

    def clear_caches(self) -> None:
        """Clear all internal caches."""
        self._makefile_cache.clear()
        self._config_cache.clear()
        self._kconfig_cache.clear()
        self._path_cache.clear()
        self._source_analysis_cache.clear()
        self._directory_priority_cache.clear()
        self._makefile_location_cache.clear()
        self._file_content_cache.clear()

        # Reset cache statistics
        for cache_type in self._cache_hits:
            self._cache_hits[cache_type] = 0
            self._cache_misses[cache_type] = 0

    # Static validation methods
    @staticmethod
    def validate_file_path(file_path: str) -> str:
        """Validate and normalize file path."""
        if not file_path or not isinstance(file_path, str):
            raise ValueError('File path must be a non-empty string')

        normalized_path = os.path.abspath(file_path)
        if not os.path.exists(normalized_path):
            raise FileNotFoundError(f'File not found: {normalized_path}')

        return normalized_path

    @staticmethod
    def validate_directory_path(dir_path: str) -> str:
        """Validate and normalize directory path."""
        if not dir_path or not isinstance(dir_path, str):
            raise ValueError('Directory path must be a non-empty string')

        normalized_path = os.path.abspath(dir_path)
        if not os.path.isdir(normalized_path):
            raise NotADirectoryError(f'Directory not found: {normalized_path}')

        return normalized_path

    @staticmethod
    def load_vex_file(file_path: str) -> Dict:
        """Load and validate VEX file."""
        normalized_path = VexKernelCheckerBase.validate_file_path(file_path)
        with open(normalized_path, 'r') as f:
            return json.load(f)

    @staticmethod
    def load_kernel_config(config_path: str) -> List[str]:
        """Load kernel configuration from file."""
        normalized_path = VexKernelCheckerBase.validate_file_path(config_path)
        config_lines = []

        with open(normalized_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Include full CONFIG lines with values
                    if line.startswith('CONFIG_') and '=' in line:
                        config_lines.append(line)
                elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
                    # Include disabled config lines for proper parsing
                    config_lines.append(line)

        return config_lines

    @staticmethod
    def save_vex_file(vex_data: Dict, file_path: str) -> None:
        """Save VEX data to file."""
        with open(file_path, 'w') as f:
            json.dump(vex_data, f, indent=2)

    def print_performance_stats(self):
        """Print performance statistics."""
        print('\n' + '=' * 60)
        print('📊 PERFORMANCE STATISTICS')
        print('=' * 60)

        print('\n💾 Cache Performance:')
        total_hits = sum(self._cache_hits.values())
        total_misses = sum(self._cache_misses.values())
        total_requests = total_hits + total_misses

        if total_requests > 0:
            overall_hit_rate = (total_hits / total_requests) * 100
            print(f'  Overall hit rate: {overall_hit_rate:.1f}%')
            print(f'  Total requests: {total_requests:,}')
            print(f'  Total hits: {total_hits:,}')
            print(f'  Total misses: {total_misses:,}')

            print('\n  Detailed breakdown:')
            for cache_type in sorted(self._cache_hits.keys()):
                hits = self._cache_hits[cache_type]
                misses = self._cache_misses[cache_type]
                total = hits + misses
                hit_rate = (hits / total * 100) if total > 0 else 0
                print(
                    f'    {cache_type.capitalize()}: {hit_rate:.1f}% ({hits}/{total})'
                )
        else:
            print('  No cache statistics available')

        # Print performance tracker summary
        self.perf_tracker.print_summary()

    def _compile_config_patterns(self) -> List[re.Pattern]:
        """Compile regex patterns for configuration extraction."""
        return [
            re.compile(r'diff --git a/(.*)\.c b/'),
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?='),
            re.compile(r'CONFIG_[A-Z0-9_]+'),
        ]

    def _compile_patch_patterns(self) -> List[re.Pattern]:
        """Compile patch-specific regex patterns."""
        return [
            re.compile(r'diff --git a/(.*)\.c b/'),
            re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)'),
            re.compile(r'#if.*defined\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
            re.compile(r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)'),
        ]

    def _compile_advanced_config_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile advanced regex patterns for config detection."""
        return {
            'primary': [
                re.compile(
                    r'obj-\$\((CONFIG_[A-Z0-9_]+)\)\s*[+:]?=\s*.*?\.o\b', re.IGNORECASE
                ),
                re.compile(
                    r'([a-zA-Z0-9_-]+)-objs-\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE
                ),
                re.compile(r'^(CONFIG_[A-Z0-9_]+)\s*[=:]', re.MULTILINE),
            ],
            'conditional': [
                re.compile(r'ifdef\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(r'ifeq\s*\(\s*\$\((CONFIG_[A-Z0-9_]+)\)', re.IGNORECASE),
            ],
            'source_hints': [
                re.compile(r'#ifn?def\s+(CONFIG_[A-Z0-9_]+)', re.IGNORECASE),
                re.compile(
                    r'IS_ENABLED\s*\(\s*(CONFIG_[A-Z0-9_]+)\s*\)', re.IGNORECASE
                ),
            ],
        }

    def _detect_architecture(self) -> str:
        """
        Detect the system architecture.

        Returns:
            String representing the detected architecture
        """
        try:
            import platform

            machine = platform.machine().lower()

            # Map common machine names to standardized architecture names
            arch_map = {
                'x86_64': 'x86_64',
                'amd64': 'x86_64',
                'i386': 'x86',
                'i486': 'x86',
                'i586': 'x86',
                'i686': 'x86',
                'aarch64': 'arm64',
                'arm64': 'arm64',
                'armv7l': 'arm',
                'armv6l': 'arm',
                'mips': 'mips',
                'mips64': 'mips64',
                'ppc64': 'powerpc',
                'ppc64le': 'powerpc',
                'powerpc': 'powerpc',
                's390x': 's390',
                'sparc64': 'sparc',
                'riscv64': 'riscv',
            }

            detected_arch = arch_map.get(machine, machine)

            if self.verbose:
                print(f'🔍 Detected architecture: {detected_arch} (from {machine})')

            return detected_arch

        except Exception as e:
            if self.verbose:
                print(f'⚠️  Error detecting architecture: {e}')
            return 'unknown'

    def get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format for VEX analysis."""
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

    def _record_cache_hit(self, cache_type: str) -> None:
        """Record a cache hit for performance tracking."""
        if cache_type in self._cache_hits:
            self._cache_hits[cache_type] += 1

    def _record_cache_miss(self, cache_type: str) -> None:
        """Record a cache miss for performance tracking."""
        if cache_type in self._cache_misses:
            self._cache_misses[cache_type] += 1

    @staticmethod
    def extract_arch_from_config(
        kernel_config: List[str],
    ) -> Tuple[Optional[str], Optional[str]]:
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
            elif (
                config_option.startswith('CONFIG_X86_')
                and config_option != 'CONFIG_X86_64'
            ):
                return 'x86', 'CONFIG_X86'
            # MIPS specific configs
            elif config_option.startswith('CONFIG_MIPS_'):
                return 'mips', 'CONFIG_MIPS'
            # PowerPC specific configs
            elif config_option.startswith('CONFIG_PPC_') or config_option.startswith(
                'CONFIG_POWERPC_'
            ):
                return 'powerpc', 'CONFIG_POWERPC'
            # RISCV specific configs
            elif config_option.startswith('CONFIG_RISCV_'):
                return 'riscv', 'CONFIG_RISCV'

        return None, None
