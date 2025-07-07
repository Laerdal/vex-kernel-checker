"""
Configuration analysis for VEX Kernel Checker.
"""

import glob
import os
import re
import time
from typing import List, Set

from .base import VexKernelCheckerBase
from .common import (
    Justification,
    VulnerabilityAnalysis,
    VulnerabilityState,
    timed_method,
)


class ConfigurationAnalyzer(VexKernelCheckerBase):
    """Analyzes kernel configurations and Makefiles to determine config requirements."""

    def __init__(self, verbose: bool = False, detailed_timing: bool = False, **kwargs):
        """Initialize configuration analyzer."""
        super().__init__(verbose=verbose, detailed_timing=detailed_timing, **kwargs)

        # Compile regex patterns for configuration analysis
        self._config_patterns = self._compile_config_patterns()
        self._advanced_config_patterns = self._compile_advanced_config_patterns()

        if self.verbose:
            print('Configuration Analyzer initialized')

    @timed_method
    def extract_config_options_from_makefile(
        self, makefile_path: str, source_file_name: str
    ) -> Set[str]:
        """Extract configuration options from Makefile using recursive analysis."""
        processed_files = set()
        return self._extract_config_recursive_optimized(
            makefile_path, source_file_name, processed_files
        )

    def _extract_config_recursive_optimized(
        self, makefile_path: str, source_file_name: str, processed_files: Set[str]
    ) -> Set[str]:
        """Optimized recursive configuration extraction with caching."""
        # Prevent infinite recursion
        if (
            makefile_path in processed_files
            or len(processed_files) > self.MAX_INCLUDE_FILES_PER_MAKEFILE
        ):
            return set()

        processed_files.add(makefile_path)

        # Check cache first
        cache_key = f'{makefile_path}:{source_file_name}'
        if cache_key in self._config_cache:
            self._record_cache_hit('config')
            return self._config_cache[cache_key]

        self._record_cache_miss('config')
        config_options = set()

        try:
            makefile_vars = self._get_cached_makefile_vars(makefile_path)
            content = self._get_cached_file_content(makefile_path)

            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Extract configs from this line
                line_configs = self._extract_configs_from_line(
                    line, source_file_name, makefile_path, makefile_vars
                )
                config_options.update(line_configs)

                # Handle includes
                if line.startswith('include') or 'include' in line:
                    include_patterns = self._resolve_include_pattern(
                        line, makefile_path, makefile_vars
                    )
                    for include_path in include_patterns[
                        : self.MAX_INCLUDE_FILES_PER_MAKEFILE
                    ]:
                        if (
                            os.path.exists(include_path)
                            and include_path not in processed_files
                        ):
                            included_configs = self._extract_config_recursive_optimized(
                                include_path, source_file_name, processed_files.copy()
                            )
                            config_options.update(included_configs)

            # Cache the result
            self._config_cache[cache_key] = config_options

        except Exception as e:
            if self.verbose:
                print(f'Error processing makefile {makefile_path}: {e}')

        return config_options

    def _resolve_include_pattern(
        self, include_pattern: str, makefile_path: str, makefile_vars: dict
    ) -> List[str]:
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
                resolved_paths.extend(
                    glob_matches[: self.MAX_INCLUDE_FILES_PER_MAKEFILE]
                )
            except Exception:
                pass
        else:
            if os.path.exists(full_path):
                resolved_paths.append(full_path)

        return resolved_paths

    def _extract_configs_from_line(
        self, line: str, source_file_name: str, makefile_path: str, makefile_vars: dict
    ) -> Set[str]:
        """Extract configuration options from a single Makefile line."""
        config_options = set()

        # Expand variables in the line
        expanded_line = self._expand_makefile_variables(line, makefile_vars)

        # Check if line references our source file
        has_source_ref = (
            source_file_name in expanded_line
            or source_file_name.replace('.c', '.o') in expanded_line
        )

        # Skip lines that don't reference our file and aren't conditional
        if not has_source_ref and not any(
            keyword in expanded_line.lower() for keyword in ['ifdef', 'ifeq', 'ifneq']
        ):
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
        """Expand Makefile variables in a line."""
        expanded = line

        # Handle $(VAR) and ${VAR} syntax
        def replace_var(match):
            var_name = match.group(1)
            return makefile_vars.get(var_name, match.group(0))

        expanded = re.sub(r'\$\(([^)]+)\)', replace_var, expanded)
        expanded = re.sub(r'\$\{([^}]+)\}', replace_var, expanded)

        return expanded

    @timed_method
    def _find_kconfig_dependencies(
        self, config_option: str, kernel_source_path: str
    ) -> Set[str]:
        """Find Kconfig dependencies for a configuration option."""
        dependencies = set()

        # Cache check
        cache_key = f'{config_option}:{kernel_source_path}'
        if cache_key in self._kconfig_cache:
            self._record_cache_hit('config')
            return self._kconfig_cache[cache_key]

        self._record_cache_miss('config')

        # Look for Kconfig files
        kconfig_patterns = ['Kconfig*', '*/Kconfig*', '**/Kconfig*']

        kconfig_files = []
        for pattern in kconfig_patterns:
            try:
                matches = glob.glob(
                    os.path.join(kernel_source_path, pattern), recursive=True
                )
                kconfig_files.extend(
                    matches[:50]
                )  # Limit to prevent excessive processing
            except Exception:
                continue

        # Parse Kconfig files
        for kconfig_file in kconfig_files[:20]:  # Process only first 20 files
            try:
                file_deps = self._parse_kconfig_file(kconfig_file, config_option)
                dependencies.update(file_deps)
            except Exception as e:
                if self.verbose:
                    print(f'Error parsing Kconfig file {kconfig_file}: {e}')

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
                    in_target_config = current_config == target_config.replace(
                        'CONFIG_', ""
                    )

                # Extract dependencies if we're in the target config
                if in_target_config:
                    if line.startswith('depends on ') or line.startswith('select '):
                        dep_line = line.replace('depends on ', "").replace(
                            'select ', ""
                        )
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
    def find_makefile_config_options(
        self, source_file_path: str, makefile_path: str, kernel_source_path: str
    ) -> Set[str]:
        """Find configuration options for a source file from a specific Makefile."""
        # Extract just the filename
        source_file_name = os.path.basename(source_file_path)

        # Get configs from this Makefile
        config_options = self.extract_config_options_from_makefile(
            makefile_path, source_file_name
        )

        # Add Kconfig dependencies
        all_configs = set(config_options)
        for config in list(config_options):
            dependencies = self._find_kconfig_dependencies(config, kernel_source_path)
            all_configs.update(dependencies)

        filtered_configs = self._filter_relevant_config_options(all_configs)
        if self.verbose and filtered_configs:
            print(
                f'Found {len(filtered_configs)} config options for {source_file_name}'
            )

        return filtered_configs

    @timed_method
    def find_makefiles_config_options(
        self, source_file_path: str, kernel_source_path: str
    ) -> Set[str]:
        """Find all relevant Makefiles and extract configuration options."""
        config_options = set()

        # Cache check
        cache_key = f'makefiles:{source_file_path}:{kernel_source_path}'
        if cache_key in self._config_cache:
            self._record_cache_hit('config')
            return self._config_cache[cache_key]

        self._record_cache_miss('config')

        # Use optimized makefile finding
        makefiles = self._find_makefiles_fast(kernel_source_path, source_file_path)

        # Process makefiles in priority order
        for makefile_path in makefiles[: self.MAX_MAKEFILE_SEARCH_FILES]:
            try:
                makefile_configs = self.find_makefile_config_options(
                    source_file_path, makefile_path, kernel_source_path
                )
                config_options.update(makefile_configs)
            except Exception as e:
                if self.verbose:
                    print(f'Error processing makefile {makefile_path}: {e}')

        # Add advanced source-based analysis
        advanced_configs = self._advanced_config_search(
            source_file_path, kernel_source_path
        )
        config_options.update(advanced_configs)

        # Cache result
        self._config_cache[cache_key] = config_options

        if self.verbose:
            print(
                f'Total {len(config_options)} config options found for {source_file_path}'
            )

        return config_options

    def _find_makefiles_fast(
        self, kernel_source_path: str, source_file_path: str
    ) -> List[str]:
        """Fast Makefile discovery with intelligent prioritization."""
        makefiles = []

        # Cache check
        cache_key = f'makefiles_fast:{kernel_source_path}:{source_file_path}'
        if cache_key in self._makefile_location_cache:
            self._record_cache_hit('makefile')
            return self._makefile_location_cache[cache_key]

        self._record_cache_miss('makefile')

        try:
            # Start from source file directory and work up
            rel_path = os.path.relpath(source_file_path, kernel_source_path)
            search_dirs = []

            # Add directories in priority order
            path_parts = rel_path.split(os.sep)
            for i in range(len(path_parts)):
                partial_path = os.path.join(kernel_source_path, *path_parts[: i + 1])
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
                            priority = self._get_directory_priority(
                                search_dir, source_file_path
                            )
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
                print(f'Error in fast makefile discovery: {e}')

        return makefiles

    def _get_directory_priority(
        self, directory_path: str, source_file_path: str
    ) -> int:
        """Calculate priority score for a directory (lower = higher priority)."""
        # Check cache
        cache_key = f'{directory_path}:{source_file_path}'
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

    def _filter_relevant_config_options(self, config_options: Set[str]) -> Set[str]:
        """Filter configuration options to remove irrelevant ones."""
        filtered = set()

        # Filter patterns for irrelevant configs
        irrelevant_patterns = [
            r'CONFIG_.*_DEBUG.*',
            r'CONFIG_.*_TEST.*',
            r'CONFIG_COMPILE_TEST',
            r'CONFIG_.*_SELFTEST.*',
        ]

        for config in config_options:
            is_relevant = True

            # Check against irrelevant patterns
            for pattern in irrelevant_patterns:
                if re.match(pattern, config):
                    is_relevant = False
                    break

            if is_relevant:
                filtered.add(config)

        return filtered

    def _advanced_config_search(
        self, source_file_path: str, kernel_source_path: str
    ) -> Set[str]:
        """Advanced configuration search using source file analysis."""
        config_options = set()

        try:
            # Check if source file exists and analyze it directly
            if os.path.exists(source_file_path):
                content = self._get_cached_file_content(source_file_path)

                # Extract config options from source code
                for pattern in self._config_patterns:
                    matches = pattern.findall(content)
                    for match in matches:
                        if isinstance(match, tuple):
                            config_option = match[0] if match else ""
                        else:
                            config_option = match

                        if config_option and config_option.startswith('CONFIG_'):
                            config_options.add(config_option)

        except Exception as e:
            if self.verbose:
                print(f'Error in advanced config search for {source_file_path}: {e}')

        return config_options

    def in_kernel_config(
        self, config_options: Set[str], kernel_config: List[str]
    ) -> VulnerabilityAnalysis:
        """
        Check if required configuration options are enabled in the kernel config.

        Args:
            config_options: Set of configuration options required for the vulnerability
            kernel_config: List of enabled configuration options in the kernel

        Returns:
            VulnerabilityAnalysis with appropriate state and justification
        """
        if not config_options:
            # No config requirements found, assume it might be in triage
            return VulnerabilityAnalysis(
                state=VulnerabilityState.IN_TRIAGE,
                justification=Justification.CODE_NOT_PRESENT,
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            )

        # Convert kernel config to set for faster lookup
        enabled_configs = set(kernel_config)

        # Add commonly enabled configs that might not be explicitly listed
        enabled_configs.update(self.ENABLED_DEFAULT_OPTIONS)

        # Check filesystem patterns and specific configs
        required_configs = set()
        optional_configs = set()

        for config in config_options:
            # Classify configs as required vs optional based on patterns
            if any(pattern in config for pattern in ['_CORE', '_BASE', '_SUPPORT']):
                required_configs.add(config)
            else:
                optional_configs.add(config)

        # If no required configs, treat all as required
        if not required_configs:
            required_configs = config_options
            optional_configs = set()

        # Check if any required config is enabled
        enabled_required = required_configs & enabled_configs
        enabled_optional = optional_configs & enabled_configs

        if enabled_required or enabled_optional:
            # At least some relevant configs are enabled
            detail_parts = []
            if enabled_required:
                detail_parts.append(
                    f'Required configs enabled: {', '.join(sorted(enabled_required))}'
                )
            if enabled_optional:
                detail_parts.append(
                    f'Optional configs enabled: {', '.join(sorted(enabled_optional))}'
                )

            detail = '; '.join(detail_parts)

            return VulnerabilityAnalysis(
                state=VulnerabilityState.EXPLOITABLE,
                justification=Justification.REQUIRES_CONFIGURATION,
                detail=detail,
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            )
        else:
            # No relevant configs are enabled
            detail = (
                f'Required configs not enabled: {', '.join(sorted(required_configs))}'
            )

            return VulnerabilityAnalysis(
                state=VulnerabilityState.NOT_AFFECTED,
                justification=Justification.CODE_NOT_PRESENT,
                detail=detail,
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            )

    def find_config_options_for_file(
        self, source_file_path: str, kernel_source_path: str
    ) -> Set[str]:
        """
        Find configuration options for a specific source file.

        Args:
            source_file_path: Path to the source file (relative to kernel source)
            kernel_source_path: Path to kernel source directory

        Returns:
            Set of configuration options related to the source file
        """
        config_options = set()

        try:
            # Use existing method to find config options via Makefiles
            makefile_configs = self.find_makefiles_config_options(
                source_file_path, kernel_source_path
            )
            config_options.update(makefile_configs)

            # For source files, also try advanced config search
            if source_file_path.endswith(('.c', '.h')):
                advanced_configs = self._advanced_config_search(
                    source_file_path, kernel_source_path
                )
                config_options.update(advanced_configs)

            # For Makefiles, extract config options directly
            if 'Makefile' in source_file_path or source_file_path.endswith('.mk'):
                full_path = os.path.join(kernel_source_path, source_file_path)
                if os.path.exists(full_path):
                    makefile_configs = self.extract_config_options_from_makefile(
                        full_path, ""
                    )
                    config_options.update(makefile_configs)

            if self.verbose and config_options:
                print(
                    f'Found {len(config_options)} config options for {source_file_path}: {', '.join(sorted(config_options))}'
                )

        except Exception as e:
            if self.verbose:
                print(f'Error analyzing {source_file_path}: {e}')

        return config_options
