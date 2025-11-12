#!/usr/bin/env python3
"""
Architecture Manager for VEX Kernel Checker.

This module handles architecture detection and architecture-specific operations:
- System architecture detection
- Architecture compatibility validation
- Architecture-specific configuration mapping
"""

# flake8: noqa: SC200

import os
import platform
import subprocess
from typing import Any, Dict, List, Optional, Set

from .base import VexKernelCheckerBase
from .common import timed_method


class ArchitectureManager(VexKernelCheckerBase):
    """Manages architecture detection and compatibility checking."""

    def __init__(self, **kwargs):
        """Initialize the ArchitectureManager.

        Args:
            **kwargs: Additional keyword arguments passed to the base class.
        """
        # Initialize architecture-specific mappings before calling super().__init__
        # because super().__init__ calls _detect_architecture which needs these mappings
        self._arch_config_mapping = self._init_arch_config_mapping()
        self._arch_aliases = self._init_arch_aliases()
        super().__init__(**kwargs)

    def _init_arch_config_mapping(self) -> Dict[str, Set[str]]:
        """Initialize architecture-specific configuration mapping."""
        return {
            "x86_64": {
                "CONFIG_X86_64",
                "CONFIG_X86",
                "CONFIG_64BIT",
                "CONFIG_X86_LOCAL_APIC",
                "CONFIG_X86_IO_APIC",
                "CONFIG_X86_TSC",
                "CONFIG_X86_MCE",
                "CONFIG_X86_PLATFORM_DEVICES",
            },
            "x86": {
                "CONFIG_X86",
                "CONFIG_X86_32",
                "CONFIG_X86_LOCAL_APIC",
                "CONFIG_X86_IO_APIC",
                "CONFIG_X86_TSC",
                "CONFIG_X86_MCE",
            },
            "arm64": {
                "CONFIG_ARM64",
                "CONFIG_64BIT",
                "CONFIG_ARM",
                "CONFIG_ARM_AMBA",
                "CONFIG_ARM_DMA_USE_IOMMU",
                "CONFIG_ARM_GIC",
                "CONFIG_ARM_ARCH_TIMER",
            },
            "arm": {
                "CONFIG_ARM",
                "CONFIG_ARM_AMBA",
                "CONFIG_ARM_DMA_USE_IOMMU",
                "CONFIG_ARM_GIC",
                "CONFIG_ARM_ARCH_TIMER",
            },
            "mips": {
                "CONFIG_MIPS",
                "CONFIG_MIPS32",
                "CONFIG_MIPS64",
                "CONFIG_CPU_MIPS32",
                "CONFIG_CPU_MIPS64",
            },
            "powerpc": {
                "CONFIG_PPC",
                "CONFIG_PPC32",
                "CONFIG_PPC64",
                "CONFIG_POWERPC",
                "CONFIG_PPC_BOOK3S",
            },
            "riscv": {"CONFIG_RISCV", "CONFIG_RISCV_SBI", "CONFIG_64BIT"},
            "s390": {"CONFIG_S390", "CONFIG_64BIT", "CONFIG_S390_HYPFS"},
            "sparc": {
                "CONFIG_SPARC",
                "CONFIG_SPARC32",
                "CONFIG_SPARC64",
                "CONFIG_64BIT",
            },
        }

    def _init_arch_aliases(self) -> Dict[str, str]:
        """Initialize architecture aliases for normalization."""
        return {
            "amd64": "x86_64",
            "x64": "x86_64",
            "i386": "x86",
            "i486": "x86",
            "i586": "x86",
            "i686": "x86",
            "aarch64": "arm64",
            "armv8": "arm64",
            "armv7": "arm",
            "armv6": "arm",
            "ppc": "powerpc",
            "ppc32": "powerpc",
            "ppc64": "powerpc",
            "ppc64le": "powerpc",
            "mips32": "mips",
            "mips64": "mips",
            "riscv32": "riscv",
            "riscv64": "riscv",
            "s390x": "s390",
            "sparc32": "sparc",
            "sparc64": "sparc",
        }

    @timed_method
    def _detect_architecture(self) -> str:
        """
        Detect system architecture using multiple methods.

        Returns:
            Detected architecture string or None if detection fails
        """
        if self.verbose:
            print("🔍 Detecting system architecture...")

        # Method 1: Try uname -m
        try:
            result = subprocess.run(
                ["uname", "-m"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                arch = result.stdout.strip().lower()
                normalized = self._normalize_architecture(arch)
                if normalized:
                    if self.verbose:
                        print(f"   ✅ Detected via uname -m: {arch} -> {normalized}")
                    return normalized
        except (
            subprocess.TimeoutExpired,
            subprocess.SubprocessError,
            FileNotFoundError,
        ):
            pass

        # Method 2: Try platform.machine()
        try:
            arch = platform.machine().lower()
            normalized = self._normalize_architecture(arch)
            if normalized:
                if self.verbose:
                    print(
                        f"   ✅ Detected via platform.machine(): {arch} -> {normalized}"
                    )
                return normalized
        except Exception:
            pass

        # Method 3: Try os.uname()
        try:
            arch = os.uname().machine.lower()
            normalized = self._normalize_architecture(arch)
            if normalized:
                if self.verbose:
                    print(f"   ✅ Detected via os.uname(): {arch} -> {normalized}")
                return normalized
        except Exception:
            pass

        # Method 4: Check /proc/cpuinfo
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read().lower()

            # Look for architecture indicators
            if "aarch64" in cpuinfo or "arm64" in cpuinfo:
                if self.verbose:
                    print("   ✅ Detected via /proc/cpuinfo: arm64")
                return "arm64"
            elif "armv7" in cpuinfo or "armv6" in cpuinfo:
                if self.verbose:
                    print("   ✅ Detected via /proc/cpuinfo: arm")
                return "arm"
            elif "x86_64" in cpuinfo or "amd64" in cpuinfo:
                if self.verbose:
                    print("   ✅ Detected via /proc/cpuinfo: x86_64")
                return "x86_64"
            elif "i386" in cpuinfo or "i686" in cpuinfo:
                if self.verbose:
                    print("   ✅ Detected via /proc/cpuinfo: x86")
                return "x86"
        except (FileNotFoundError, PermissionError):
            pass

        # Method 5: Check kernel config for architecture
        config_paths = [
            "/proc/config.gz",
            "/boot/config-" + platform.release(),
            "/proc/config",
        ]

        for config_path in config_paths:
            try:
                arch = self._detect_arch_from_config(config_path)
                if arch:
                    if self.verbose:
                        print(f"   ✅ Detected via {config_path}: {arch}")
                    return arch
            except Exception:
                continue

        if self.verbose:
            print("   ❌ Could not detect architecture")
        return "unknown"

    def _normalize_architecture(self, arch: str) -> Optional[str]:
        """
        Normalize architecture string using aliases.

        Args:
            arch: Raw architecture string

        Returns:
            Normalized architecture or None if unknown
        """
        arch = arch.lower().strip()

        # Direct match
        if arch in self._arch_config_mapping:
            return arch

        # Alias match
        if arch in self._arch_aliases:
            return self._arch_aliases[arch]

        # Partial matches for common variations
        if "x86_64" in arch or "amd64" in arch:
            return "x86_64"
        elif "aarch64" in arch or "arm64" in arch:
            return "arm64"
        elif "armv" in arch and ("7" in arch or "6" in arch):
            return "arm"
        elif "i386" in arch or "i686" in arch:
            return "x86"
        elif "mips" in arch:
            return "mips"
        elif "ppc" in arch or "powerpc" in arch:
            return "powerpc"
        elif "riscv" in arch:
            return "riscv"
        elif "s390" in arch:
            return "s390"
        elif "sparc" in arch:
            return "sparc"

        return None

    def _detect_arch_from_config(self, config_path: str) -> Optional[str]:
        """
        Detect architecture from kernel configuration file.

        Args:
            config_path: Path to kernel config file

        Returns:
            Detected architecture or None
        """
        try:
            import gzip

            # Handle compressed config
            if config_path.endswith(".gz"):
                with gzip.open(config_path, "rt") as f:
                    config_content = f.read()
            else:
                with open(config_path, "r") as f:
                    config_content = f.read()

            # Check for architecture-specific configs
            for arch, configs in self._arch_config_mapping.items():
                for config in configs:
                    if (
                        f"{config}=y" in config_content
                        or f"{config}=m" in config_content
                    ):
                        return arch

        except Exception:
            pass

        return None

    @timed_method
    def get_architecture_configs(self, arch: Optional[str] = None) -> Set[str]:
        """
        Get architecture-specific configuration options.

        Args:
            arch: Architecture name (uses detected if None)

        Returns:
            Set of architecture-specific config options
        """
        target_arch = arch or self.arch
        if not target_arch:
            return set()

        return self._arch_config_mapping.get(target_arch, set())

    @timed_method
    def is_architecture_compatible(
        self, target_arch: str, current_arch: Optional[str] = None
    ) -> bool:
        """
        Check if target architecture is compatible with current architecture.

        Args:
            target_arch: Target architecture to check
            current_arch: Current architecture (uses detected if None)

        Returns:
            True if architectures are compatible
        """
        current = current_arch or self.arch
        if not current:
            return True  # Assume compatible if can't detect

        # Normalize both architectures
        normalized_target = self._normalize_architecture(target_arch)
        normalized_current = self._normalize_architecture(current)

        if not normalized_target or not normalized_current:
            return True  # Assume compatible if can't normalize

        # Exact match
        if normalized_target == normalized_current:
            return True

        # Cross-compatibility rules
        compatibility_rules = {
            "x86_64": ["x86"],  # x86_64 can run x86 code
            "arm64": ["arm"],  # arm64 can run arm code
            "mips": ["mips32", "mips64"],  # MIPS variations
            "powerpc": ["ppc", "ppc32", "ppc64"],  # PowerPC variations
            "sparc": ["sparc32", "sparc64"],  # SPARC variations
        }

        # Check if current architecture can handle target
        compatible_archs = compatibility_rules.get(normalized_current, [])
        return normalized_target in compatible_archs

    @timed_method
    def get_supported_architectures(self) -> List[str]:
        """
        Get list of supported architectures.

        Returns:
            List of supported architecture names
        """
        return list(self._arch_config_mapping.keys())

    @timed_method
    def validate_architecture_config(
        self, arch: str, kernel_config: List[str]
    ) -> Dict[str, Any]:
        """
        Validate that kernel configuration matches claimed architecture.

        Args:
            arch: Architecture to validate
            kernel_config: Kernel configuration lines

        Returns:
            Dictionary with validation results
        """
        normalized_arch = self._normalize_architecture(arch)
        if not normalized_arch:
            return {"valid": False, "reason": f"Unknown architecture: {arch}"}

        required_configs = self.get_architecture_configs(normalized_arch)
        if not required_configs:
            return {"valid": True, "reason": "No specific configs required"}

        # Parse kernel config
        enabled_configs = set()
        for line in kernel_config:
            line = line.strip()
            if line.startswith("CONFIG_") and "=" in line:
                config_name, value = line.split("=", 1)
                if value in ["y", "m"]:
                    enabled_configs.add(config_name)

        # Check if any required configs are enabled
        found_configs = required_configs.intersection(enabled_configs)

        if found_configs:
            return {
                "valid": True,
                "reason": f'Found architecture configs: {", ".join(sorted(found_configs))}',
                "found_configs": found_configs,
                "missing_configs": required_configs - found_configs,
            }
        else:
            return {
                "valid": False,
                "reason": f"No {normalized_arch} architecture configs found",
                "missing_configs": required_configs,
            }

    @timed_method
    def get_architecture(self) -> Optional[str]:
        """Get the current detected architecture."""
        return self.arch

    @timed_method
    def get_architecture_info(self) -> Dict[str, Any]:
        """
        Get comprehensive architecture information.

        Returns:
            Dictionary with architecture details
        """
        return {
            "detected": self.arch,
            "supported": self.get_supported_architectures(),
            "aliases": self._arch_aliases,
            "configs": self.get_architecture_configs() if self.arch else {},
            "detection_methods": [
                "uname -m",
                "platform.machine()",
                "os.uname()",
                "/proc/cpuinfo",
                "kernel config",
            ],
        }
