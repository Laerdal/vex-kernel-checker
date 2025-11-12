#!/usr/bin/env python3
"""
Unit tests for VEX Kernel Checker common components.

Tests the shared data structures, enums, and utilities.
"""

import unittest
import time
from vex_kernel_checker.common import (
    VulnerabilityState,
    Justification,
    Response,
    VulnerabilityAnalysis,
    CVEInfo,
    PerformanceTracker,
)


class TestEnums(unittest.TestCase):
    """Test cases for enum definitions."""

    def test_vulnerability_state_values(self):
        """Test VulnerabilityState enum values match CycloneDX v1.6."""
        self.assertEqual(VulnerabilityState.RESOLVED.value, "resolved")
        self.assertEqual(
            VulnerabilityState.RESOLVED_WITH_PEDIGREE.value, "resolved_with_pedigree"
        )
        self.assertEqual(VulnerabilityState.EXPLOITABLE.value, "exploitable")
        self.assertEqual(VulnerabilityState.IN_TRIAGE.value, "in_triage")
        self.assertEqual(VulnerabilityState.FALSE_POSITIVE.value, "false_positive")
        self.assertEqual(VulnerabilityState.NOT_AFFECTED.value, "not_affected")

    def test_justification_values(self):
        """Test Justification enum values."""
        self.assertEqual(Justification.CODE_NOT_PRESENT.value, "code_not_present")
        self.assertEqual(Justification.CODE_NOT_REACHABLE.value, "code_not_reachable")
        self.assertEqual(
            Justification.REQUIRES_CONFIGURATION.value, "requires_configuration"
        )
        self.assertEqual(Justification.REQUIRES_DEPENDENCY.value, "requires_dependency")

    def test_response_values(self):
        """Test Response enum values."""
        self.assertEqual(Response.CAN_NOT_FIX.value, "can_not_fix")
        self.assertEqual(Response.WILL_NOT_FIX.value, "will_not_fix")
        self.assertEqual(Response.UPDATE.value, "update")
        self.assertEqual(Response.ROLLBACK.value, "rollback")


class TestVulnerabilityAnalysis(unittest.TestCase):
    """Test cases for VulnerabilityAnalysis data class."""

    def test_minimal_analysis_creation(self):
        """Test creating VulnerabilityAnalysis with minimal required fields."""
        analysis = VulnerabilityAnalysis(state=VulnerabilityState.EXPLOITABLE)

        self.assertEqual(analysis.state, VulnerabilityState.EXPLOITABLE)
        self.assertIsNone(analysis.justification)
        self.assertIsNone(analysis.response)
        self.assertIsNone(analysis.detail)
        self.assertIsNone(analysis.lastUpdated)

    def test_complete_analysis_creation(self):
        """Test creating VulnerabilityAnalysis with all fields."""
        lastUpdated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        analysis = VulnerabilityAnalysis(
            state=VulnerabilityState.NOT_AFFECTED,
            justification=Justification.CODE_NOT_PRESENT,
            response=Response.WILL_NOT_FIX,
            detail="Driver not compiled in kernel",
            lastUpdated=lastUpdated,
        )

        self.assertEqual(analysis.state, VulnerabilityState.NOT_AFFECTED)
        self.assertEqual(analysis.justification, Justification.CODE_NOT_PRESENT)
        self.assertEqual(analysis.response, Response.WILL_NOT_FIX)
        self.assertEqual(analysis.detail, "Driver not compiled in kernel")
        self.assertEqual(analysis.lastUpdated, lastUpdated)

    def test_to_dict_minimal(self):
        """Test to_dict with minimal fields."""
        analysis = VulnerabilityAnalysis(state=VulnerabilityState.IN_TRIAGE)
        result = analysis.to_dict()

        expected = {"state": "in_triage"}
        self.assertEqual(result, expected)

    def test_to_dict_complete(self):
        """Test to_dict with all fields."""
        lastUpdated = "2025-01-01T12:00:00Z"
        analysis = VulnerabilityAnalysis(
            state=VulnerabilityState.EXPLOITABLE,
            justification=Justification.REQUIRES_CONFIGURATION,
            response=Response.CAN_NOT_FIX,
            detail="All required configs enabled",
            lastUpdated=lastUpdated,
        )
        result = analysis.to_dict()

        expected = {
            "state": "exploitable",
            "justification": "requires_configuration",
            "response": [
                "can_not_fix"
            ],  # Per CycloneDX 1.5 spec, response must be array
            "detail": "All required configs enabled",
            "lastUpdated": "2025-01-01T12:00:00Z",
        }
        self.assertEqual(result, expected)

    def test_to_dict_partial(self):
        """Test to_dict with some optional fields."""
        analysis = VulnerabilityAnalysis(
            state=VulnerabilityState.FALSE_POSITIVE,
            justification=Justification.CODE_NOT_REACHABLE,
            detail="Code path never executed",
        )
        result = analysis.to_dict()

        expected = {
            "state": "false_positive",
            "justification": "code_not_reachable",
            "detail": "Code path never executed",
        }
        self.assertEqual(result, expected)


class TestCVEInfo(unittest.TestCase):
    """Test cases for CVEInfo data class."""

    def test_minimal_cve_info(self):
        """Test creating CVEInfo with minimal fields."""
        cve = CVEInfo(cve_id="CVE-2023-12345")

        self.assertEqual(cve.cve_id, "CVE-2023-12345")
        self.assertIsNone(cve.severity)
        self.assertIsNone(cve.cvss_score)
        self.assertIsNone(cve.description)
        self.assertIsNone(cve.patch_urls)

    def test_complete_cve_info(self):
        """Test creating CVEInfo with all fields."""
        patch_urls = ["https://github.com/torvalds/linux/commit/abc123"]
        cve = CVEInfo(
            cve_id="CVE-2023-12345",
            severity="HIGH",
            cvss_score=7.5,
            description="Buffer overflow in driver",
            patch_urls=patch_urls,
            published_date="2023-01-01",
            modified_date="2023-01-02",
        )

        self.assertEqual(cve.cve_id, "CVE-2023-12345")
        self.assertEqual(cve.severity, "HIGH")
        self.assertEqual(cve.cvss_score, 7.5)
        self.assertEqual(cve.description, "Buffer overflow in driver")
        self.assertEqual(cve.patch_urls, patch_urls)
        self.assertEqual(cve.published_date, "2023-01-01")
        self.assertEqual(cve.modified_date, "2023-01-02")


class TestPerformanceTracker(unittest.TestCase):
    """Test cases for PerformanceTracker."""

    def setUp(self):
        """Set up test fixtures."""
        self.tracker = PerformanceTracker()

    def test_initialization(self):
        """Test PerformanceTracker initialization."""
        self.assertIsInstance(self.tracker.timings, dict)
        self.assertIsInstance(self.tracker.cache_stats, dict)
        self.assertEqual(len(self.tracker.timings), 0)
        self.assertEqual(len(self.tracker.cache_stats), 0)

    def test_record_timing(self):
        """Test recording timing information."""
        self.tracker.record_timing("test_operation", 1.5)

        self.assertIn("test_operation", self.tracker.timings)
        self.assertEqual(self.tracker.timings["test_operation"], 1.5)

    def test_record_cache_hit(self):
        """Test recording cache hit."""
        self.tracker.record_cache_hit("test_cache")

        self.assertIn("test_cache", self.tracker.cache_stats)
        self.assertEqual(self.tracker.cache_stats["test_cache"]["hits"], 1)
        self.assertEqual(self.tracker.cache_stats["test_cache"]["misses"], 0)

    def test_record_cache_miss(self):
        """Test recording cache miss."""
        self.tracker.record_cache_miss("test_cache")

        self.assertIn("test_cache", self.tracker.cache_stats)
        self.assertEqual(self.tracker.cache_stats["test_cache"]["hits"], 0)
        self.assertEqual(self.tracker.cache_stats["test_cache"]["misses"], 1)

    def test_mixed_cache_operations(self):
        """Test mixed cache hits and misses."""
        cache_name = "mixed_cache"

        # Record hits and misses
        self.tracker.record_cache_hit(cache_name)
        self.tracker.record_cache_hit(cache_name)
        self.tracker.record_cache_miss(cache_name)

        stats = self.tracker.cache_stats[cache_name]
        self.assertEqual(stats["hits"], 2)
        self.assertEqual(stats["misses"], 1)

    def test_get_summary(self):
        """Test getting performance summary."""
        # Record some data
        self.tracker.record_timing("operation_1", 1.0)
        self.tracker.record_timing("operation_2", 2.5)
        self.tracker.record_cache_hit("cache_1")
        self.tracker.record_cache_miss("cache_1")

        summary = self.tracker.get_summary()

        self.assertIn("total_operations", summary)
        self.assertIn("total_time", summary)
        self.assertIn("cache_summary", summary)

        self.assertEqual(summary["total_operations"], 2)
        self.assertEqual(summary["total_time"], 3.5)

        cache_summary = summary["cache_summary"]["cache_1"]
        self.assertEqual(cache_summary["hits"], 1)
        self.assertEqual(cache_summary["misses"], 1)
        self.assertEqual(cache_summary["hit_rate"], 50.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
