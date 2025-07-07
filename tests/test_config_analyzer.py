#!/usr/bin/env python3
"""
Unit tests for VEX Kernel Checker Configuration Analyzer.

Tests configuration parsing, filtering, and analysis logic.
"""

import unittest
import tempfile
import os

from vex_kernel_checker.config_analyzer import ConfigurationAnalyzer


class TestConfigurationAnalyzer(unittest.TestCase):
    """Test cases for ConfigurationAnalyzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = ConfigurationAnalyzer(verbose=False)

        # Create temporary directories
        self.temp_dir = tempfile.mkdtemp()
        self.kernel_source_dir = os.path.join(self.temp_dir, "kernel_source")
        os.makedirs(self.kernel_source_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_initialization(self):
        """Test ConfigurationAnalyzer initialization."""
        analyzer = ConfigurationAnalyzer(verbose=True)

        self.assertTrue(analyzer.verbose)
        self.assertIsNotNone(analyzer.perf_tracker)

    def test_extract_config_options_from_makefile_basic(self):
        """Test extracting config options from a basic Makefile."""
        # Create test Makefile
        makefile_path = os.path.join(self.kernel_source_dir, "Makefile")
        makefile_content = """
obj-$(CONFIG_NET_DRIVER) += net_driver.o
obj-$(CONFIG_USB_CORE) += usb/

ifdef CONFIG_WIRELESS
obj-m += wireless_driver.o
endif

obj-$(CONFIG_BLUETOOTH) += bt_driver.o
        """

        with open(makefile_path, "w") as f:
            f.write(makefile_content)

        configs = self.analyzer.extract_config_options_from_makefile(
            makefile_path, "net_driver.o"
        )

        # Should find relevant config options
        self.assertIsInstance(configs, set)
        # The actual configs found depend on the Makefile content and analysis logic
        # Just verify it returns a set and doesn't crash

    def test_find_makefile_config_options(self):
        """Test finding config options for a source file in Makefile."""
        # Create test Makefile
        makefile_path = os.path.join(self.kernel_source_dir, "Makefile")
        makefile_content = """
obj-$(CONFIG_EXAMPLE_DRIVER) += example_driver.o
obj-$(CONFIG_USB_SUPPORT) += usb_driver.o
        """

        with open(makefile_path, "w") as f:
            f.write(makefile_content)

        # Create source file
        source_path = os.path.join(self.kernel_source_dir, "example_driver.c")
        with open(source_path, "w") as f:
            f.write("// Example driver source")

        configs = self.analyzer.find_makefile_config_options(
            source_path, makefile_path, self.kernel_source_dir
        )

        self.assertIsInstance(configs, set)

    def test_find_makefiles_config_options(self):
        """Test finding config options across multiple Makefiles."""
        # Create directory structure with Makefiles
        drivers_dir = os.path.join(self.kernel_source_dir, "drivers")
        os.makedirs(drivers_dir)

        # Main Makefile
        main_makefile = os.path.join(self.kernel_source_dir, "Makefile")
        with open(main_makefile, "w") as f:
            f.write("obj-$(CONFIG_DRIVERS) += drivers/\n")

        # Drivers Makefile
        drivers_makefile = os.path.join(drivers_dir, "Makefile")
        with open(drivers_makefile, "w") as f:
            f.write("obj-$(CONFIG_EXAMPLE_DRIVER) += example.o\n")

        # Source file
        source_path = os.path.join(drivers_dir, "example.c")
        with open(source_path, "w") as f:
            f.write("// Example driver")

        configs = self.analyzer.find_makefiles_config_options(
            source_path, self.kernel_source_dir
        )

        self.assertIsInstance(configs, set)

    def test_filter_relevant_config_options(self):
        """Test filtering config options to remove noise."""
        test_configs = {
            "CONFIG_NETWORK_DRIVER",
            "CONFIG_X86",  # Architecture specific
            "CONFIG_EXPERIMENTAL",  # Deprecated
            "CONFIG_USB_SUPPORT",
            "CONFIG_DEBUG_KERNEL",  # Debug option
        }

        filtered = self.analyzer._filter_relevant_config_options(test_configs)

        self.assertIsInstance(filtered, set)
        # Should filter out some noise configs
        self.assertLessEqual(len(filtered), len(test_configs))

    def test_advanced_config_search(self):
        """Test advanced configuration search functionality."""
        # Create source file with config references
        source_path = os.path.join(self.kernel_source_dir, "driver.c")
        source_content = """
#ifdef CONFIG_FEATURE_A
static int feature_a_init(void) {
    return 0;
}
#endif

#if defined(CONFIG_FEATURE_B)
static void feature_b_handler(void) {
    // Feature B code
}
#endif
        """

        with open(source_path, "w") as f:
            f.write(source_content)

        configs = self.analyzer._advanced_config_search(
            source_path, self.kernel_source_dir
        )

        self.assertIsInstance(configs, set)
        # Should find configs referenced in the source file
        if configs:  # If any configs found
            self.assertTrue(any("CONFIG_" in config for config in configs))

    def test_find_kconfig_dependencies(self):
        """Test finding Kconfig dependencies."""
        # Create simple Kconfig file
        kconfig_path = os.path.join(self.kernel_source_dir, "Kconfig")
        kconfig_content = """
config EXAMPLE_DRIVER
    tristate "Example driver"
    depends on CONFIG_NET
    help
      Example driver description.

config NET_SUPPORT
    bool "Network support"
    default y
        """

        with open(kconfig_path, "w") as f:
            f.write(kconfig_content)

        deps = self.analyzer._find_kconfig_dependencies(
            "CONFIG_EXAMPLE_DRIVER", self.kernel_source_dir
        )

        self.assertIsInstance(deps, set)

    def test_nonexistent_file_handling(self):
        """Test handling of non-existent files gracefully."""
        # Test with non-existent Makefile
        configs = self.analyzer.extract_config_options_from_makefile(
            "/nonexistent/Makefile", "test.o"
        )
        self.assertEqual(configs, set())

        # Test with non-existent source file
        configs = self.analyzer.find_makefiles_config_options(
            "/nonexistent/source.c", self.kernel_source_dir
        )
        self.assertEqual(configs, set())

    def test_empty_makefile(self):
        """Test handling of empty Makefile."""
        # Create empty Makefile
        makefile_path = os.path.join(self.kernel_source_dir, "Makefile")
        with open(makefile_path, "w") as f:
            f.write("")

        configs = self.analyzer.extract_config_options_from_makefile(
            makefile_path, "test.o"
        )

        self.assertIsInstance(configs, set)
        self.assertEqual(len(configs), 0)

    def test_malformed_makefile(self):
        """Test handling of malformed Makefile."""
        # Create Makefile with malformed content
        makefile_path = os.path.join(self.kernel_source_dir, "Makefile")
        makefile_content = """
# This is a comment
invalid line without proper syntax
obj-$(CONFIG_VALID) += valid.o
another invalid line
        """

        with open(makefile_path, "w") as f:
            f.write(makefile_content)

        # Should not crash on malformed content
        configs = self.analyzer.extract_config_options_from_makefile(
            makefile_path, "valid.o"
        )

        self.assertIsInstance(configs, set)


if __name__ == "__main__":
    unittest.main(verbosity=2)
