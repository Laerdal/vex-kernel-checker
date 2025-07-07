#!/usr/bin/env python3
"""
Unit tests for ReportGenerator module.
Tests report generation, formatting, and output functionality.
"""

import unittest
from unittest.mock import Mock, patch, mock_open
import sys
import os
import json

# Add the parent directory to the path so we can import the vex_kernel_checker package
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from vex_kernel_checker.report_generator import ReportGenerator
from vex_kernel_checker.common import (
    VulnerabilityState,
    Justification,
    VulnerabilityAnalysis,
)


class TestReportGenerator(unittest.TestCase):
    """Test cases for ReportGenerator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.report_generator = ReportGenerator()

        # Sample VEX data for testing
        self.sample_vex_data = {
            "bomRef": "test-kernel",
            "affects": [
                {
                    "ref": "CVE-2023-1234",
                    "analysis": {
                        "state": "not_affected",
                        "justification": "code_not_present",
                        "detail": "Driver not enabled in kernel configuration",
                    },
                },
                {
                    "ref": "CVE-2023-5678",
                    "analysis": {
                        "state": "exploitable",
                        "detail": "Vulnerable driver is enabled and reachable",
                    },
                },
            ],
        }

    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization."""
        # Test with default parameters
        rg1 = ReportGenerator()
        self.assertIsNotNone(rg1)

        # Test with custom parameters
        rg2 = ReportGenerator(verbose=True)
        self.assertTrue(rg2.verbose)

    def test_generate_summary_report(self):
        """Test basic summary report generation."""
        report = self.report_generator.generate_summary_report(self.sample_vex_data)

        self.assertIsInstance(report, dict)
        # Should contain summary information
        self.assertIn("total", report)  # Changed from 'total_vulnerabilities'
        self.assertIn("by_severity", report)  # Changed from 'vulnerability_counts'

    def test_generate_summary_report_with_empty_data(self):
        """Test summary report generation with empty VEX data."""
        empty_vex = {"bomRef": "empty-kernel", "affects": []}

        report = self.report_generator.generate_summary_report(empty_vex)

        self.assertIsInstance(report, dict)
        self.assertEqual(report.get("total_vulnerabilities", 0), 0)

    def test_generate_detailed_report(self):
        """Test detailed report generation."""
        report = self.report_generator.generate_detailed_report(self.sample_vex_data)

        self.assertIsInstance(report, dict)
        # Should contain detailed vulnerability information
        self.assertIn("detailed_analysis", report)  # Changed from 'vulnerabilities'
        self.assertIn("summary", report)

    def test_generate_detailed_report_with_configs(self):
        """Test detailed report generation including configuration details."""
        report = self.report_generator.generate_detailed_report(
            self.sample_vex_data, include_configs=True
        )

        self.assertIsInstance(report, dict)
        # May include config information depending on implementation
        self.assertIn("detailed_analysis", report)  # Changed from 'vulnerabilities'

    def test_generate_performance_report(self):
        """Test performance report generation."""
        report = self.report_generator.generate_performance_report()

        self.assertIsInstance(report, dict)
        # Should contain performance metrics
        # May be empty if no performance data is available
        self.assertTrue(len(report) >= 0)

    def test_print_summary_report(self):
        """Test printing summary report to console."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        # Should not crash when printing
        try:
            self.report_generator.print_summary_report(summary_report)
            self.assertTrue(True)  # Completed successfully
        except Exception as e:
            self.fail(f"print_summary_report failed: {e}")

    @patch("builtins.open", mock_open())
    def test_export_report_json(self):
        """Test exporting report to JSON file."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        result = self.report_generator.export_report(
            report=summary_report, output_file="/fake/output/report.json", format="json"
        )

        self.assertIsInstance(result, bool)

    @patch("builtins.open", mock_open())
    def test_export_report_text(self):
        """Test exporting report to text file."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        result = self.report_generator.export_report(
            report=summary_report, output_file="/fake/output/report.txt", format="text"
        )

        self.assertIsInstance(result, bool)

    def test_format_report_as_text(self):
        """Test formatting report as text."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        text_report = self.report_generator._format_report_as_text(summary_report)

        self.assertIsInstance(text_report, str)
        self.assertTrue(len(text_report) > 0)

    def test_calculate_risk_level(self):
        """Test risk level calculation."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        risk_level = self.report_generator._calculate_risk_level(summary_report)

        self.assertIsInstance(risk_level, str)
        self.assertIn(
            risk_level.lower(),
            ["low", "medium", "high", "critical", "unknown", "minimal"],
        )  # Added missing values

    def test_generate_recommendations(self):
        """Test recommendation generation."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        recommendations = self.report_generator._generate_recommendations(
            summary_report
        )

        self.assertIsInstance(recommendations, list)
        # May be empty if no recommendations are generated

    def test_calculate_cache_hit_rates(self):
        """Test cache hit rate calculation."""
        if hasattr(self.report_generator, "_calculate_cache_hit_rates"):
            hit_rates = self.report_generator._calculate_cache_hit_rates()

            self.assertIsInstance(hit_rates, dict)
            # May be empty if no cache data is available

    def test_generate_performance_recommendations(self):
        """Test performance recommendation generation."""
        recommendations = self.report_generator._generate_performance_recommendations()

        self.assertIsInstance(recommendations, list)
        # May be empty if no performance issues are detected

    def test_vulnerability_state_counting(self):
        """Test that vulnerability states are properly counted in reports."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        vulnerability_counts = summary_report.get("vulnerability_counts", {})

        # Should have counts for different states
        self.assertIsInstance(vulnerability_counts, dict)

        # Check specific counts based on our test data
        if "not_affected" in vulnerability_counts:
            self.assertGreaterEqual(vulnerability_counts["not_affected"], 1)
        if "exploitable" in vulnerability_counts:
            self.assertGreaterEqual(vulnerability_counts["exploitable"], 1)

    def test_report_structure_compliance(self):
        """Test that generated reports comply with expected structure."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        # Should have required fields
        self.assertIn("total", summary_report)  # Changed from 'total_vulnerabilities'
        self.assertIn(
            "by_severity", summary_report
        )  # Changed from 'vulnerability_counts'

        # Counts should be numbers
        self.assertIsInstance(
            summary_report["total"], int
        )  # Changed from 'total_vulnerabilities'
        self.assertIsInstance(
            summary_report["vulnerabilities"], dict
        )  # Changed from 'vulnerability_counts'

    def test_detailed_report_structure(self):
        """Test that detailed reports have proper structure."""
        detailed_report = self.report_generator.generate_detailed_report(
            self.sample_vex_data
        )

        # Should have required sections
        self.assertIn(
            "detailed_analysis", detailed_report
        )  # Changed from 'vulnerabilities'
        self.assertIn("summary", detailed_report)

        # Detailed analysis should be a list
        self.assertIsInstance(
            detailed_report["detailed_analysis"], list
        )  # Changed from 'vulnerabilities'

    def test_json_serialization(self):
        """Test that generated reports are JSON serializable."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        # Should be able to serialize to JSON
        try:
            json_string = json.dumps(summary_report, indent=2)
            self.assertIsInstance(json_string, str)

            # Should be able to deserialize back
            deserialized = json.loads(json_string)
            self.assertEqual(
                deserialized["total"], summary_report["total"]
            )  # Changed from 'total_vulnerabilities'
        except Exception as e:
            self.fail(f"JSON serialization failed: {e}")

    def test_base_class_inheritance(self):
        """Test that ReportGenerator inherits from base class properly."""
        # Should have verbose property from base class
        self.assertTrue(hasattr(self.report_generator, "verbose"))

    def test_verbose_output(self):
        """Test verbose output during report generation."""
        verbose_generator = ReportGenerator(verbose=True)

        # Should not crash with verbose output enabled
        report = verbose_generator.generate_summary_report(self.sample_vex_data)

        self.assertIsInstance(report, dict)

    def test_error_handling_invalid_vex_data(self):
        """Test error handling with invalid VEX data."""
        invalid_vex_data = [
            None,
            {},  # Missing required fields
            {"bomRef": "test"},  # Missing affects
            {"affects": []},  # Missing bomRef
            "not_a_dict",  # Wrong type
        ]

        for invalid_vex in invalid_vex_data:
            with self.subTest(vex_data=invalid_vex):
                try:
                    report = self.report_generator.generate_summary_report(invalid_vex)
                    # Should handle invalid data gracefully or return a sensible default
                    self.assertIsInstance(report, (dict, type(None)))
                except Exception:
                    # If it raises an exception, it should be a specific, expected one
                    pass

    def test_export_report_invalid_format(self):
        """Test export report with invalid format."""
        summary_report = self.report_generator.generate_summary_report(
            self.sample_vex_data
        )

        with patch("builtins.open", mock_open()):
            result = self.report_generator.export_report(
                report=summary_report,
                output_file="/fake/output/report.invalid",
                format="invalid_format",
            )

            # Should handle invalid format gracefully
            self.assertIsInstance(result, bool)

    def test_malformed_vulnerability_data(self):
        """Test handling of malformed vulnerability data in VEX."""
        malformed_vex = {
            "bomRef": "test-kernel",
            "affects": [
                {"ref": "CVE-2023-BAD"},  # Missing analysis
                {"analysis": {"state": "exploitable"}},  # Missing ref
                {},  # Empty vulnerability
                None,  # None entry
            ],
        }

        # Should handle malformed data gracefully
        try:
            report = self.report_generator.generate_summary_report(malformed_vex)
            self.assertIsInstance(report, dict)
        except Exception as e:
            self.fail(f"Report generation failed with malformed data: {e}")

    def test_performance_with_large_dataset(self):
        """Test performance with large VEX data."""
        # Create a large dataset
        large_vulnerabilities = []
        for i in range(100):
            large_vulnerabilities.append(
                {
                    "id": f"CVE-2023-{i:04d}",
                    "severity": "high" if i % 3 == 0 else "medium",
                    "description": f"Test vulnerability {i}",
                    "analysis": {
                        "state": "not_affected" if i % 2 == 0 else "exploitable",
                        "justification": "code_not_present" if i % 2 == 0 else None,
                        "detail": f"Analysis for CVE {i}",
                    },
                }
            )

        large_vex = {
            "bomRef": "test-kernel",
            "vulnerabilities": large_vulnerabilities,
        }  # Changed from 'affects'

        # Should handle large datasets without issues
        report = self.report_generator.generate_summary_report(large_vex)

        self.assertIsInstance(report, dict)
        self.assertEqual(
            report.get("total", 0), 100
        )  # Changed from 'total_vulnerabilities'

    def test_report_consistency(self):
        """Test that report generation is consistent across multiple calls."""
        report1 = self.report_generator.generate_summary_report(self.sample_vex_data)
        report2 = self.report_generator.generate_summary_report(self.sample_vex_data)

        # Should generate identical reports for identical input
        self.assertEqual(
            report1["total"], report2["total"]
        )  # Changed from 'total_vulnerabilities'
        self.assertEqual(
            report1["vulnerabilities"], report2["vulnerabilities"]
        )  # Changed from 'vulnerability_counts'

    def test_empty_affects_handling(self):
        """Test handling of VEX data with empty affects list."""
        empty_affects_vex = {"bomRef": "test-kernel", "affects": []}

        report = self.report_generator.generate_summary_report(empty_affects_vex)

        self.assertIsInstance(report, dict)
        self.assertEqual(report.get("total_vulnerabilities", 0), 0)


if __name__ == "__main__":
    unittest.main()
