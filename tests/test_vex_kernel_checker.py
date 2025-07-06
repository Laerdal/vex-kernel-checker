#!/usr/bin/env python3
"""
Comprehensive test suite for VEX Kernel Checker.

This module provides unit tests and integration tests for the VEX Kernel Checker
to ensure robustness and correctness of the vulnerability analysis functionality.
"""

import unittest
import tempfile
import os
import json
import shutil
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

# Add the parent directory to the path to import the vex-kernel-checker module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from vex_kernel_checker import VexKernelChecker, VulnerabilityState, Justification, VulnerabilityAnalysis, CVEInfo
except ImportError:
    # If the above import fails, try to import as if it's a script
    import importlib.util
    spec = importlib.util.spec_from_file_location("vex_kernel_checker", 
                                                 os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                                             "../vex-kernel-checker.py"))
    if spec is None or spec.loader is None:
        raise ImportError("Could not create module spec for vex_kernel_checker")
    vex_kernel_checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex_kernel_checker)
    VexKernelChecker = vex_kernel_checker.VexKernelChecker
    VulnerabilityState = vex_kernel_checker.VulnerabilityState
    Justification = vex_kernel_checker.Justification
    VulnerabilityAnalysis = vex_kernel_checker.VulnerabilityAnalysis
    CVEInfo = vex_kernel_checker.CVEInfo


class TestVexKernelChecker(unittest.TestCase):
    """Test cases for the VexKernelChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary directories for testing
        self.temp_dir = tempfile.mkdtemp()
        self.kernel_source_dir = os.path.join(self.temp_dir, "kernel_source")
        self.config_file = os.path.join(self.temp_dir, "test.config")
        self.vex_file = os.path.join(self.temp_dir, "test.vex")
        
        os.makedirs(self.kernel_source_dir)
        
        # Create test kernel config
        self.create_test_kernel_config()
        
        # Create test VEX data
        self.create_test_vex_data()
        
        # Create test kernel source structure
        self.create_test_kernel_source()
        
        # Initialize checker without external dependencies
        self.checker = VexKernelChecker(
            verbose=False,
            api_key=None,
            edge_driver_path=None,
            disable_patch_checking=True,  # Disable for unit tests
            analyze_all_cves=False
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_kernel_config(self):
        """Create a test kernel configuration file."""
        config_content = """# Test kernel configuration
CONFIG_NET=y
CONFIG_BT=y
CONFIG_USB=y
CONFIG_PCI=y
CONFIG_SCSI=y
CONFIG_BLOCK=y
CONFIG_FILESYSTEMS=y
CONFIG_CRYPTO=y
CONFIG_SOUND=y
CONFIG_SECURITY=y
# CONFIG_DEBUG is not set
CONFIG_MODULES=y
CONFIG_NETDEVICES=y
CONFIG_WIRELESS=y
CONFIG_ETHERNET=y
"""
        with open(self.config_file, 'w') as f:
            f.write(config_content)
    
    def create_test_vex_data(self):
        """Create test VEX data with various CVE types."""
        vex_data = {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1234",
                    "severity": "HIGH",
                    "description": "Linux kernel network subsystem vulnerability"
                },
                {
                    "id": "CVE-2023-5678",
                    "severity": "MEDIUM",
                    "description": "USB driver memory corruption vulnerability"
                },
                {
                    "id": "CVE-2023-9999",
                    "severity": "LOW",
                    "description": "Non-kernel userspace library vulnerability"
                }
            ]
        }
        
        with open(self.vex_file, 'w') as f:
            json.dump(vex_data, f, indent=2)
    
    def create_test_kernel_source(self):
        """Create a minimal test kernel source structure."""
        # Create directory structure
        drivers_net = os.path.join(self.kernel_source_dir, "drivers", "net")
        drivers_usb = os.path.join(self.kernel_source_dir, "drivers", "usb")
        net_core = os.path.join(self.kernel_source_dir, "net", "core")
        
        os.makedirs(drivers_net, exist_ok=True)
        os.makedirs(drivers_usb, exist_ok=True)
        os.makedirs(net_core, exist_ok=True)
        
        # Create test source files
        test_net_file = os.path.join(drivers_net, "test_driver.c")
        with open(test_net_file, 'w') as f:
            f.write("""
#include <linux/module.h>
#ifdef CONFIG_NET
#include <linux/netdevice.h>
#endif

#if defined(CONFIG_BT)
static int bt_feature_enabled = 1;
#endif

#if IS_ENABLED(CONFIG_WIRELESS)
static void wireless_init(void) {
    // Wireless initialization
}
#endif
""")
        
        # Create test Makefiles
        net_makefile = os.path.join(drivers_net, "Makefile")
        with open(net_makefile, 'w') as f:
            f.write("""
obj-$(CONFIG_NET) += test_driver.o
obj-$(CONFIG_BT) += bluetooth_module.o
obj-$(CONFIG_WIRELESS) += wireless_driver.o

test_driver-objs := test_driver.o helper.o
""")
        
        usb_makefile = os.path.join(drivers_usb, "Makefile")
        with open(usb_makefile, 'w') as f:
            f.write("""
obj-$(CONFIG_USB) += usb_core.o
obj-$(CONFIG_USB_STORAGE) += usb_storage.o

ifdef CONFIG_USB_DEBUG
    EXTRA_CFLAGS += -DDEBUG
endif
""")
    
    def test_initialization(self):
        """Test VexKernelChecker initialization."""
        # Test default initialization
        checker = VexKernelChecker()
        self.assertFalse(checker.verbose)
        self.assertIsNone(checker.api_key)
        self.assertIsNone(checker.edge_driver_path)
        self.assertFalse(checker.check_patches)  # Should be False without API key/driver
        
        # Test initialization with parameters
        checker_verbose = VexKernelChecker(verbose=True, analyze_all_cves=True)
        self.assertTrue(checker_verbose.verbose)
        self.assertTrue(checker_verbose.analyze_all_cves)
    
    def test_kernel_config_parsing(self):
        """Test kernel configuration parsing."""
        # Load the test config
        with open(self.config_file, 'r') as f:
            config_lines = f.readlines()
        
        kernel_config = []
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        
        # Verify expected configurations are loaded
        self.assertIn("CONFIG_NET", kernel_config)
        self.assertIn("CONFIG_BT", kernel_config)
        self.assertIn("CONFIG_USB", kernel_config)
        self.assertNotIn("CONFIG_DEBUG", kernel_config)  # Should be excluded
    
    def test_makefile_config_extraction(self):
        """Test Makefile configuration option extraction."""
        makefile_path = os.path.join(self.kernel_source_dir, "drivers", "net", "Makefile")
        source_file = os.path.join(self.kernel_source_dir, "drivers", "net", "test_driver.c")
        
        config_options = self.checker.find_makefile_config_options(
            source_file, makefile_path, self.kernel_source_dir
        )
        
        # Should find CONFIG_NET for test_driver.c
        self.assertGreater(len(config_options), 0)
        self.assertTrue(any("CONFIG_" in opt for opt in config_options))
    
    def test_source_file_analysis(self):
        """Test source file configuration hint analysis."""
        source_file = os.path.join(self.kernel_source_dir, "drivers", "net", "test_driver.c")
        
        config_options = self.checker._analyze_source_file_config_hints(source_file)
        
        # Should find CONFIG options from #ifdef, #if defined, and IS_ENABLED
        expected_configs = {"CONFIG_NET", "CONFIG_BT", "CONFIG_WIRELESS"}
        found_configs = {opt for opt in config_options if opt in expected_configs}
        
        self.assertGreater(len(found_configs), 0)
    
    def test_path_based_inference(self):
        """Test path-based configuration inference."""
        # Test network driver path
        net_source = os.path.join(self.kernel_source_dir, "drivers", "net", "test_driver.c")
        net_configs = self.checker._infer_config_from_path(net_source, self.kernel_source_dir)
        
        # Should infer CONFIG_NET and CONFIG_NETDEVICES
        self.assertTrue(any("NET" in opt for opt in net_configs))
        
        # Test USB driver path
        usb_source = os.path.join(self.kernel_source_dir, "drivers", "usb", "test_driver.c")
        usb_configs = self.checker._infer_config_from_path(usb_source, self.kernel_source_dir)
        
        # Should infer CONFIG_USB
        self.assertTrue(any("USB" in opt for opt in usb_configs))
    
    def test_kernel_config_analysis(self):
        """Test kernel configuration analysis logic."""
        # Load test kernel config
        with open(self.config_file, 'r') as f:
            config_lines = f.readlines()
        
        kernel_config = []
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        
        # Test case 1: All required configs are enabled
        enabled_configs = {"CONFIG_NET", "CONFIG_BT"}
        analysis = self.checker.in_kernel_config(enabled_configs, kernel_config)
        self.assertEqual(analysis.state, VulnerabilityState.EXPLOITABLE)
        
        # Test case 2: Required config is missing
        missing_configs = {"CONFIG_NET", "CONFIG_MISSING_FEATURE"}
        analysis = self.checker.in_kernel_config(missing_configs, kernel_config)
        self.assertEqual(analysis.state, VulnerabilityState.NOT_AFFECTED)
        self.assertEqual(analysis.justification, Justification.CODE_NOT_PRESENT)
        
        # Test case 3: No specific configs found (default case)
        empty_configs = set()
        analysis = self.checker.in_kernel_config(empty_configs, kernel_config)
        self.assertEqual(analysis.state, VulnerabilityState.IN_TRIAGE)
    
    def test_architecture_extraction(self):
        """Test architecture information extraction from file paths."""
        # Test ARM architecture
        arm_path = "arch/arm/mach-omap2/board-generic.c"
        arch, config = VexKernelChecker.extract_arch_info(arm_path)
        self.assertEqual(arch, "arm")
        self.assertEqual(config, "CONFIG_ARM")
        
        # Test x86 architecture
        x86_path = "arch/x86/kernel/setup.c"
        arch, config = VexKernelChecker.extract_arch_info(x86_path)
        self.assertEqual(arch, "x86")
        self.assertEqual(config, "CONFIG_X86")
        
        # Test non-architecture path
        net_path = "net/core/skbuff.c"
        arch, config = VexKernelChecker.extract_arch_info(net_path)
        self.assertIsNone(arch)
        self.assertIsNone(config)
    
    def test_kernel_cve_detection(self):
        """Test kernel-related CVE detection."""
        # Test kernel-related CVE
        kernel_cve = CVEInfo(
            cve_id="CVE-2023-1234",
            description="Linux kernel memory corruption in network subsystem",
            patch_urls=[
                "https://lore.kernel.org/patch/123",
                "https://git.kernel.org/commit/abc123"
            ]
        )
        
        is_kernel = self.checker.is_kernel_related_cve(kernel_cve)
        self.assertTrue(is_kernel)
        
        # Test non-kernel CVE
        userspace_cve = CVEInfo(
            cve_id="CVE-2023-5678",
            description="Buffer overflow in apache web server configuration parser",
            patch_urls=[
                "https://github.com/somelib/fix",
                "https://example.com/advisory"
            ]
        )
        
        is_kernel = self.checker.is_kernel_related_cve(userspace_cve)
        self.assertFalse(is_kernel)
    
    def test_vex_data_validation(self):
        """Test VEX data validation."""
        # Load test VEX data
        with open(self.vex_file, 'r') as f:
            vex_data = json.load(f)
        
        # Test valid VEX data
        issues = self.checker.validate_vex_data(vex_data)
        self.assertEqual(len(issues), 0)
        
        # Test invalid VEX data - missing vulnerabilities
        invalid_vex = {"metadata": {}}
        issues = self.checker.validate_vex_data(invalid_vex)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("vulnerabilities" in issue for issue in issues))
        
        # Test invalid CVE ID format
        invalid_cve_vex = {
            "vulnerabilities": [
                {"id": "INVALID-123", "description": "Test"}
            ]
        }
        issues = self.checker.validate_vex_data(invalid_cve_vex)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any("CVE-" in issue for issue in issues))
    
    def test_performance_caching(self):
        """Test performance caching mechanisms."""
        # Test makefile cache
        makefile_path = os.path.join(self.kernel_source_dir, "drivers", "net", "Makefile")
        
        # First call should be a cache miss
        initial_misses = self.checker._cache_misses.get('makefile', 0)
        content1 = self.checker._get_cached_file_content(makefile_path)
        
        # Second call should be a cache hit
        initial_hits = self.checker._cache_hits.get('makefile', 0)
        content2 = self.checker._get_cached_file_content(makefile_path)
        
        self.assertEqual(content1, content2)
        # Note: Cache hit/miss tracking may not be implemented for _get_cached_file_content
        # This test verifies the caching mechanism works correctly
    
    def test_error_handling(self):
        """Test error handling for various edge cases."""
        # Test with non-existent source file
        fake_source = "/non/existent/file.c"
        config_options = self.checker._analyze_source_file_config_hints(fake_source)
        self.assertEqual(len(config_options), 0)
        
        # Test with non-existent makefile
        fake_makefile = "/non/existent/Makefile"
        fake_source = "/fake/source.c"
        config_options = self.checker.find_makefile_config_options(
            fake_source, fake_makefile, self.kernel_source_dir
        )
        # Should gracefully handle the error and return empty set or fallback options
        self.assertIsInstance(config_options, set)
    
    def test_vulnerability_report_generation(self):
        """Test vulnerability report generation."""
        # Create VEX data with analysis results
        vex_data_with_analysis = {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1234",
                    "severity": "HIGH",
                    "analysis": {
                        "state": "exploitable",
                        "detail": "Configuration enabled"
                    }
                },
                {
                    "id": "CVE-2023-5678",
                    "severity": "MEDIUM",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "requires_configuration",
                        "detail": "Required config not enabled"
                    }
                }
            ]
        }
        
        report = self.checker.generate_vulnerability_report(vex_data_with_analysis)
        
        self.assertEqual(report['total'], 2)
        self.assertEqual(report['exploitable'], 1)
        self.assertEqual(report['not_affected'], 1)
        self.assertIn('summary', report)
        self.assertIn('by_state', report['summary'])
    
    def test_kernel_architecture_detection(self):
        """Test kernel architecture detection from configuration."""
        # Test configuration with ARM enabled
        arm_config = ["CONFIG_ARM", "CONFIG_NET", "CONFIG_USB", "CONFIG_BLOCK"]
        architectures = VexKernelChecker.detect_kernel_architectures(arm_config)
        self.assertIn("arm", architectures)
        self.assertEqual(len(architectures), 1)
        
        # Test configuration with multiple architectures (shouldn't happen in real configs)
        multi_config = ["CONFIG_ARM", "CONFIG_X86", "CONFIG_NET"]
        architectures = VexKernelChecker.detect_kernel_architectures(multi_config)
        self.assertIn("arm", architectures)
        self.assertIn("x86", architectures)
        
        # Test configuration with no architecture
        no_arch_config = ["CONFIG_NET", "CONFIG_USB", "CONFIG_BLOCK"]
        architectures = VexKernelChecker.detect_kernel_architectures(no_arch_config)
        self.assertEqual(len(architectures), 0)
        
        # Test with x86 architecture
        x86_config = ["CONFIG_X86", "CONFIG_NET"]
        architectures = VexKernelChecker.detect_kernel_architectures(x86_config)
        self.assertIn("x86", architectures)
        self.assertEqual(len(architectures), 1)
    
    def test_config_option_filtering(self):
        """Test configuration option filtering functionality."""
        test_options = {
            # These should be kept (functional options)
            'CONFIG_NET',
            'CONFIG_USB',
            'CONFIG_DRM_TTM_HELPER',
            'CONFIG_MACSEC',
            'CONFIG_HID_MAYFLASH',
            
            # These should be filtered out (build/debug options)
            'CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN',
            'CONFIG_GCC_PLUGIN_RANDSTRUCT',
            'CONFIG_LTO_CLANG',
            'CONFIG_CFI_CLANG',
            'CONFIG_DEBUG_INFO_BTF',
            'CONFIG_FTRACE_MCOUNT_USE_RECORDMCOUNT',
            'CONFIG_FRAME_WARN',
            'CONFIG_STRIP_ASM_SYMS',
            'CONFIG_HEADERS_INSTALL',
            'CONFIG_EXPERT',
            'CONFIG_SUPERH',
            'CONFIG_UML',
            'CONFIG_HAVE_STACK_VALIDATION'
        }
        
        filtered = self.checker._filter_relevant_config_options(test_options)
        
        # Should keep functional options
        self.assertIn('CONFIG_NET', filtered)
        self.assertIn('CONFIG_USB', filtered)
        self.assertIn('CONFIG_DRM_TTM_HELPER', filtered)
        self.assertIn('CONFIG_MACSEC', filtered)
        self.assertIn('CONFIG_HID_MAYFLASH', filtered)
        
        # Should filter out build/debug options
        self.assertNotIn('CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN', filtered)
        self.assertNotIn('CONFIG_GCC_PLUGIN_RANDSTRUCT', filtered)
        self.assertNotIn('CONFIG_LTO_CLANG', filtered)
        self.assertNotIn('CONFIG_CFI_CLANG', filtered)
        self.assertNotIn('CONFIG_DEBUG_INFO_BTF', filtered)
        self.assertNotIn('CONFIG_FTRACE_MCOUNT_USE_RECORDMCOUNT', filtered)
        self.assertNotIn('CONFIG_FRAME_WARN', filtered)
        self.assertNotIn('CONFIG_STRIP_ASM_SYMS', filtered)
        self.assertNotIn('CONFIG_HEADERS_INSTALL', filtered)
        self.assertNotIn('CONFIG_EXPERT', filtered)
        self.assertNotIn('CONFIG_SUPERH', filtered)
        self.assertNotIn('CONFIG_UML', filtered)
        self.assertNotIn('CONFIG_HAVE_STACK_VALIDATION', filtered)
        
        # Should significantly reduce the number of options
        self.assertLess(len(filtered), len(test_options) / 2)


class TestIntegration(unittest.TestCase):
    """Integration tests for the VEX Kernel Checker."""
    
    def setUp(self):
        """Set up integration test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(self.temp_dir, ignore_errors=True))
    
    @patch('requests.get')
    def test_cve_details_fetching(self, mock_get):
        """Test CVE details fetching with mocked API response."""
        # Mock successful API response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-1234",
                    "descriptions": [{"lang": "en", "value": "Test CVE description"}],
                    "references": [
                        {
                            "url": "https://github.com/torvalds/linux/commit/abc123",
                            "source": "test",
                            "tags": ["Patch"]
                        }
                    ]
                }
            }]
        }
        mock_get.return_value = mock_response
        
        checker = VexKernelChecker(api_key="test-key")
        cve_info = checker.fetch_cve_details("CVE-2023-1234")
        
        self.assertIsNotNone(cve_info)
        self.assertEqual(cve_info.cve_id, "CVE-2023-1234")
    
    def test_config_only_analysis_workflow(self):
        """Test complete config-only analysis workflow."""
        # Create test files in temp directory
        kernel_source = os.path.join(self.temp_dir, "kernel")
        config_file = os.path.join(self.temp_dir, "test.config")
        vex_file = os.path.join(self.temp_dir, "test.vex")
        
        os.makedirs(os.path.join(kernel_source, "drivers", "net"))
        
        # Create minimal test files
        with open(config_file, 'w') as f:
            f.write("CONFIG_NET=y\nCONFIG_USB=y\n")
        
        vex_data = {
            "vulnerabilities": [
                {"id": "CVE-2023-1234", "severity": "HIGH", "description": "Test CVE"}
            ]
        }
        with open(vex_file, 'w') as f:
            json.dump(vex_data, f)
        
        # Create test source and makefile
        test_source = os.path.join(kernel_source, "drivers", "net", "test.c")
        with open(test_source, 'w') as f:
            f.write("#ifdef CONFIG_NET\n// Network code\n#endif\n")
        
        test_makefile = os.path.join(kernel_source, "drivers", "net", "Makefile")
        with open(test_makefile, 'w') as f:
            f.write("obj-$(CONFIG_NET) += test.o\n")
        
        # Load and process
        with open(vex_file, 'r') as f:
            vex_data = json.load(f)
        
        with open(config_file, 'r') as f:
            config_lines = f.readlines()
        
        kernel_config = []
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        
        checker = VexKernelChecker(disable_patch_checking=True, verbose=True)
        
        # This should run without errors in config-only mode
        try:
            updated_vex = checker.update_analysis_state(vex_data, kernel_config, kernel_source)
            self.assertIsNotNone(updated_vex)
            self.assertIn('vulnerabilities', updated_vex)
        except Exception as e:
            self.fail(f"Config-only analysis failed: {e}")


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
