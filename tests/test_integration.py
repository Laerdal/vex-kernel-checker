#!/usr/bin/env python3
"""
Integration tests for the VEX Kernel Checker.

These tests verify the complete end-to-end functionality of the modular package.
"""

import unittest
import json
import tempfile
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the modular components
from vex_kernel_checker.main_checker import VexKernelChecker


class TestIntegration(unittest.TestCase):
    """Integration tests for end-to-end functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Create sample VEX data for testing
        self.sample_vex_data = {
            "vulnerabilities": [
                {
                    "id": "CVE-2023-1234",
                    "description": "Test kernel vulnerability in network driver",
                    "severity": "high",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_present",
                        "detail": "Driver not included in kernel configuration",
                    },
                },
                {
                    "id": "CVE-2023-5678",
                    "description": "USB subsystem vulnerability",
                    "severity": "medium",
                    # No analysis - should be analyzed by the tool
                },
            ]
        }

        # Create sample kernel config
        self.sample_config = [
            "CONFIG_NET=y",
            "CONFIG_USB=m",
            "CONFIG_X86_64=y",
            "CONFIG_MODULES=y",
        ]

    def test_end_to_end_analysis(self):
        """Test complete end-to-end analysis workflow."""
        # Initialize the main checker
        checker = VexKernelChecker(
            verbose=False,  # Keep output quiet for tests
            check_patches=False,  # Skip patch fetching for faster tests
            analyze_all_cves=True,
        )

        # Run analysis on sample data
        result = checker.analyze_vulnerabilities(
            vex_data=self.sample_vex_data,
            kernel_config=self.sample_config,
            kernel_source_path="/tmp",  # Dummy path for test
        )

        # Verify the result
        self.assertIsInstance(result, dict)

        # Should have vulnerabilities
        self.assertIn("vulnerabilities", result)
        vulnerabilities = result["vulnerabilities"]
        self.assertEqual(len(vulnerabilities), 2)

        # First CVE should keep its existing analysis
        cve_1 = next((v for v in vulnerabilities if v["id"] == "CVE-2023-1234"), None)
        self.assertIsNotNone(cve_1)
        if cve_1:
            self.assertEqual(cve_1["analysis"]["state"], "not_affected")

        # Second CVE should get analyzed (if kernel-related detection works)
        cve_2 = next((v for v in vulnerabilities if v["id"] == "CVE-2023-5678"), None)
        self.assertIsNotNone(cve_2)
        if cve_2:
            # Should have some analysis result (even if it's empty state)
            self.assertIn("analysis", cve_2)

    def test_report_generation(self):
        """Test report generation functionality."""
        checker = VexKernelChecker(verbose=False)

        # Generate a summary report
        report = checker.report_generator.generate_summary_report(self.sample_vex_data)

        # Verify report structure
        self.assertIsInstance(report, dict)
        self.assertIn("total", report)
        self.assertIn("summary", report)
        self.assertEqual(report["total"], 2)

    def test_configuration_analysis(self):
        """Test configuration analysis functionality."""
        checker = VexKernelChecker(verbose=False)

        # Test that the config analyzer exists and works
        self.assertIsNotNone(checker.config_analyzer)
        # Just verify the analyzer can be initialized without errors

    def test_architecture_detection(self):
        """Test architecture detection functionality."""
        checker = VexKernelChecker(verbose=False)

        # Test architecture detection
        arch_info = checker.architecture_manager.get_architecture_info()

        # Should return valid architecture information
        self.assertIsInstance(arch_info, dict)
        self.assertIn("detected", arch_info)
        self.assertIn("supported", arch_info)

    def test_vulnerability_analysis_components(self):
        """Test that all vulnerability analysis components work together."""
        checker = VexKernelChecker(verbose=False)

        # Create a test CVE
        from vex_kernel_checker.common import CVEInfo

        test_cve = CVEInfo(
            cve_id="CVE-2023-TEST",
            description="Test Linux kernel driver vulnerability",
            severity="medium",
        )

        # Test kernel-related detection
        is_kernel_related = checker.cve_manager.is_kernel_related_cve(test_cve)
        self.assertIsInstance(is_kernel_related, bool)

    def test_modular_initialization(self):
        """Test that all modular components initialize correctly."""
        checker = VexKernelChecker(
            verbose=True, check_patches=True, analyze_all_cves=True, arch="x86_64"
        )

        # Verify all components are initialized
        self.assertIsNotNone(checker.cve_manager)
        self.assertIsNotNone(checker.patch_manager)
        self.assertIsNotNone(checker.config_analyzer)
        self.assertIsNotNone(checker.vulnerability_analyzer)
        self.assertIsNotNone(checker.architecture_manager)
        self.assertIsNotNone(checker.report_generator)

        # Verify configuration propagation
        self.assertTrue(checker.verbose)
        self.assertTrue(checker.check_patches)
        self.assertTrue(checker.analyze_all_cves)
        self.assertEqual(checker.arch, "x86_64")


if __name__ == "__main__":
    unittest.main(verbosity=2)
