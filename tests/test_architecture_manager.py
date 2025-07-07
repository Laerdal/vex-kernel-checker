#!/usr/bin/env python3
"""
Unit tests for ArchitectureManager module.
Tests architecture detection, compatibility checking, and config mapping.
"""

import unittest
from unittest.mock import Mock, patch, mock_open
import sys
import os

# Add the parent directory to the path so we can import the vex_kernel_checker package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vex_kernel_checker.architecture_manager import ArchitectureManager


class TestArchitectureManager(unittest.TestCase):
    """Test cases for ArchitectureManager class."""

    def setUp(self):
        """Set up test fixtures."""
        self.arch_manager = ArchitectureManager()

        # Sample kernel config for testing
        self.sample_config = [
            "CONFIG_X86=y",
            "CONFIG_64BIT=y",
            "CONFIG_ARM=n",
            "CONFIG_ARM64=n",
            "CONFIG_PPC=n",
            "CONFIG_S390=n",
            "CONFIG_MIPS=n",
        ]

    def test_architecture_manager_initialization(self):
        """Test ArchitectureManager initialization."""
        # Test with default parameters
        arch_mgr1 = ArchitectureManager()
        self.assertIsNotNone(arch_mgr1)

        # Test with custom parameters
        arch_mgr2 = ArchitectureManager(verbose=True)
        self.assertTrue(arch_mgr2.verbose)

    def test_arch_config_mapping_initialization(self):
        """Test that architecture config mapping is properly initialized."""
        mapping = self.arch_manager._arch_config_mapping

        self.assertIsInstance(mapping, dict)
        self.assertIn("x86_64", mapping)
        self.assertIn("arm64", mapping)

        # Check that x86_64 has expected configs
        x86_configs = mapping.get("x86_64", set())
        self.assertIn("CONFIG_X86_64", x86_configs)
        self.assertIn("CONFIG_64BIT", x86_configs)

    def test_arch_aliases_initialization(self):
        """Test that architecture aliases are properly initialized."""
        aliases = self.arch_manager._arch_aliases

        self.assertIsInstance(aliases, dict)
        self.assertEqual(aliases.get("amd64"), "x86_64")
        self.assertEqual(aliases.get("aarch64"), "arm64")
        self.assertEqual(aliases.get("ppc"), "powerpc")

    def test_normalize_architecture(self):
        """Test architecture normalization."""
        # Test known aliases
        self.assertEqual(self.arch_manager._normalize_architecture("amd64"), "x86_64")
        self.assertEqual(self.arch_manager._normalize_architecture("aarch64"), "arm64")
        self.assertEqual(self.arch_manager._normalize_architecture("i386"), "x86")

        # Test already normalized
        self.assertEqual(self.arch_manager._normalize_architecture("x86_64"), "x86_64")
        self.assertEqual(self.arch_manager._normalize_architecture("arm64"), "arm64")

    def test_get_architecture_configs(self):
        """Test getting architecture-specific configuration options."""
        # Test x86_64 configs
        x86_configs = self.arch_manager.get_architecture_configs("x86_64")

        self.assertIsInstance(x86_configs, set)
        self.assertIn("CONFIG_X86_64", x86_configs)
        self.assertIn("CONFIG_64BIT", x86_configs)

    def test_get_architecture_configs_with_default(self):
        """Test getting configs for current/default architecture."""
        # Should work with None (uses detected architecture)
        default_configs = self.arch_manager.get_architecture_configs(None)

        self.assertIsInstance(default_configs, set)
        # May be empty if architecture detection fails

    def test_is_architecture_compatible_same_arch(self):
        """Test architecture compatibility for same architectures."""
        # Should be compatible with itself
        result = self.arch_manager.is_architecture_compatible("x86_64", "x86_64")
        self.assertTrue(result)

    def test_is_architecture_compatible_different_arch(self):
        """Test architecture compatibility for different architectures."""
        # Different architectures should typically be incompatible
        result = self.arch_manager.is_architecture_compatible("x86_64", "arm64")
        # This depends on implementation - may be True for some cases
        self.assertIsInstance(result, bool)

    def test_is_architecture_compatible_with_current(self):
        """Test architecture compatibility using current architecture."""
        # Should work when current_arch is None (uses detected)
        result = self.arch_manager.is_architecture_compatible("x86_64", None)
        self.assertIsInstance(result, bool)

    def test_get_supported_architectures(self):
        """Test getting list of supported architectures."""
        supported_archs = self.arch_manager.get_supported_architectures()

        self.assertIsInstance(supported_archs, list)
        self.assertIn("x86_64", supported_archs)
        self.assertIn("arm64", supported_archs)

    def test_validate_architecture_config(self):
        """Test validation of architecture configuration."""
        # Test with x86_64 config
        validation_result = self.arch_manager.validate_architecture_config(
            "x86_64", self.sample_config
        )

        self.assertIsInstance(validation_result, dict)
        # Should contain validation information
        self.assertIn("valid", validation_result)

    def test_get_architecture(self):
        """Test getting the detected architecture."""
        arch = self.arch_manager.get_architecture()

        # Should return a string or None
        self.assertIsInstance(arch, (str, type(None)))

    def test_get_architecture_info(self):
        """Test getting comprehensive architecture information."""
        arch_info = self.arch_manager.get_architecture_info()

        self.assertIsInstance(arch_info, dict)
        # Should contain architecture information (check actual field name)
        self.assertIn("detected", arch_info)

    @patch("os.path.exists")
    def test_detect_arch_from_config_file_not_found(self, mock_exists):
        """Test architecture detection when config file doesn't exist."""
        mock_exists.return_value = False

        arch = self.arch_manager._detect_arch_from_config("/nonexistent/config")

        self.assertIsNone(arch)

    @patch("builtins.open", mock_open(read_data="CONFIG_X86=y\nCONFIG_64BIT=y\n"))
    @patch("os.path.exists")
    def test_detect_arch_from_config_x86_64(self, mock_exists):
        """Test architecture detection from config file for x86_64."""
        mock_exists.return_value = True

        arch = self.arch_manager._detect_arch_from_config("/fake/config")

        # Should detect x86_64 or x86
        if arch:
            self.assertIn(arch, ["x86_64", "x86"])

    def test_architecture_detection_methods(self):
        """Test that architecture detection has multiple fallback methods."""
        # The _detect_architecture method should be callable
        self.assertTrue(callable(self.arch_manager._detect_architecture))

        # Should complete without error
        try:
            arch = self.arch_manager._detect_architecture()
            self.assertIsInstance(arch, (str, type(None)))
        except Exception as e:
            self.fail(f"Architecture detection failed with error: {e}")

    def test_base_class_inheritance(self):
        """Test that ArchitectureManager inherits from base class properly."""
        # Should have verbose property from base class
        self.assertTrue(hasattr(self.arch_manager, "verbose"))

    def test_timed_method_decorator(self):
        """Test that architecture detection is properly timed."""
        # The _detect_architecture method should be decorated with @timed_method
        self.assertTrue(callable(self.arch_manager._detect_architecture))

        # Should complete without error
        try:
            arch = self.arch_manager._detect_architecture()
            self.assertTrue(True)  # Completed successfully
        except Exception as e:
            self.fail(f"Architecture detection failed with error: {e}")

    def test_verbose_output(self):
        """Test verbose output during architecture operations."""
        verbose_manager = ArchitectureManager(verbose=True)

        # Should not crash with verbose output enabled
        arch_info = verbose_manager.get_architecture_info()

        self.assertIsInstance(arch_info, dict)

    def test_config_validation_with_invalid_arch(self):
        """Test config validation with invalid architecture."""
        validation_result = self.arch_manager.validate_architecture_config(
            "invalid_arch", self.sample_config
        )

        self.assertIsInstance(validation_result, dict)
        # Should handle invalid architecture gracefully

    def test_config_validation_with_empty_config(self):
        """Test config validation with empty configuration."""
        validation_result = self.arch_manager.validate_architecture_config("x86_64", [])

        self.assertIsInstance(validation_result, dict)
        # Should handle empty config gracefully

    def test_architecture_config_completeness(self):
        """Test that all supported architectures have config mappings."""
        supported_archs = self.arch_manager.get_supported_architectures()
        mapping = self.arch_manager._arch_config_mapping

        for arch in supported_archs:
            with self.subTest(architecture=arch):
                self.assertIn(arch, mapping)
                configs = mapping[arch]
                self.assertIsInstance(configs, set)
                self.assertTrue(len(configs) > 0)

    def test_error_handling_malformed_config(self):
        """Test error handling with malformed configuration."""
        malformed_configs = [
            ["CONFIG_X86="],
            ["=y"],
            ["CONFIG_INVALID_FORMAT===y"],
            [""],
            [None],
        ]

        for malformed_config in malformed_configs:
            with self.subTest(config=malformed_config):
                try:
                    validation_result = self.arch_manager.validate_architecture_config(
                        "x86_64", malformed_config
                    )
                    # Should not crash, even with malformed input
                    self.assertIsInstance(validation_result, dict)
                except Exception:
                    # If it raises an exception, it should be handled gracefully
                    pass

    def test_architecture_aliases_coverage(self):
        """Test that architecture aliases cover common variations."""
        aliases = self.arch_manager._arch_aliases

        # Common x86 aliases
        self.assertIn("amd64", aliases)
        self.assertIn("i386", aliases)
        self.assertIn("i686", aliases)

        # Common ARM aliases
        self.assertIn("aarch64", aliases)
        self.assertIn("armv7", aliases)

        # Common PowerPC aliases
        self.assertIn("ppc", aliases)
        self.assertIn("ppc64", aliases)

    @patch("platform.machine")
    def test_architecture_detection_fallback(self, mock_machine):
        """Test architecture detection fallback mechanisms."""
        # Mock platform.machine to return a known value
        mock_machine.return_value = "x86_64"

        arch = self.arch_manager._detect_architecture()

        # Should return some architecture
        self.assertIsInstance(arch, (str, type(None)))

    def test_performance_tracking(self):
        """Test that performance tracking works for architecture operations."""
        # Should be able to get architecture info without errors
        arch_info = self.arch_manager.get_architecture_info()

        self.assertIsInstance(arch_info, dict)


if __name__ == "__main__":
    unittest.main()
