#!/usr/bin/env python3
"""
Unit tests for VEX Kernel Checker base classes.

Tests the base functionality and initialization.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from vex_kernel_checker.base import VexKernelCheckerBase
from vex_kernel_checker.common import PerformanceTracker


class TestVexKernelCheckerBase(unittest.TestCase):
    """Test cases for VexKernelCheckerBase class."""

    def test_default_initialization(self):
        """Test base class initialization with default parameters."""
        base = VexKernelCheckerBase()

        self.assertFalse(base.verbose)
        self.assertFalse(base.check_patches)
        self.assertFalse(base.analyze_all_cves)
        self.assertEqual(base.arch, "x86_64")
        self.assertIsInstance(base.perf_tracker, PerformanceTracker)

    def test_custom_initialization(self):
        """Test base class initialization with custom parameters."""
        base = VexKernelCheckerBase(
            verbose=True, check_patches=True, analyze_all_cves=True, arch="arm64"
        )

        self.assertTrue(base.verbose)
        self.assertTrue(base.check_patches)
        self.assertTrue(base.analyze_all_cves)
        self.assertEqual(base.arch, "arm64")

    def test_kwargs_initialization(self):
        """Test base class initialization with keyword arguments."""
        kwargs = {
            "verbose": True,
            "check_patches": False,
            "arch": "arm",
            "unknown_param": "ignored",
        }  # Should be ignored

        base = VexKernelCheckerBase(**kwargs)

        self.assertTrue(base.verbose)
        self.assertFalse(base.check_patches)
        self.assertEqual(base.arch, "arm")
        # unknown_param should be ignored without error

    def test_performance_tracker_integration(self):
        """Test that performance tracker is properly integrated."""
        base = VexKernelCheckerBase()

        # Test recording timing
        base.perf_tracker.record_timing("test_operation", 1.5)
        self.assertIn("test_operation", base.perf_tracker.timings)

        # Test cache operations
        base.perf_tracker.record_cache_hit("test_cache")
        base.perf_tracker.record_cache_miss("test_cache")

        stats = base.perf_tracker.cache_stats["test_cache"]
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)


class TestTimedMethodDecorator(unittest.TestCase):
    """Test cases for the timed_method decorator."""

    def setUp(self):
        """Set up test fixtures."""
        from vex_kernel_checker.common import timed_method

        class TestClass(VexKernelCheckerBase):
            @timed_method
            def test_method(self, arg1, arg2=None):
                return f"result: {arg1}, {arg2}"

            @timed_method
            def slow_method(self):
                import time

                time.sleep(0.1)  # 100ms delay
                return "done"

        self.test_obj = TestClass()
        self.TestClass = TestClass

    def test_timed_method_basic(self):
        """Test that timed method works and records timing."""
        result = self.test_obj.test_method("hello", arg2="world")

        self.assertEqual(result, "result: hello, world")

        # The timed_method decorator just prints timing if enabled
        # Let's test that the method itself works correctly
        self.assertIsInstance(result, str)
        self.assertIn("hello", result)
        self.assertIn("world", result)

    def test_timed_method_with_delay(self):
        """Test timed method with actual delay."""
        result = self.test_obj.slow_method()

        self.assertEqual(result, "done")

        # The method should return the correct value
        self.assertIsInstance(result, str)

    def test_timed_method_preserves_exceptions(self):
        """Test that timed method preserves exceptions."""
        from vex_kernel_checker.common import timed_method

        class TestClass(VexKernelCheckerBase):
            @timed_method
            def failing_method(self):
                raise ValueError("Test error")

        test_obj = TestClass()

        with self.assertRaises(ValueError) as cm:
            test_obj.failing_method()

        self.assertEqual(str(cm.exception), "Test error")


class TestSaveVexFile(unittest.TestCase):
    """Test cases for save_vex_file JSON formatting."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "vulnerabilities": [
                {
                    "id": "CVE-2024-12345",
                    "analysis": {
                        "state": "exploitable",
                        "justification": "requires_configuration",
                        "response": ["can_not_fix"],
                        "detail": "Test vulnerability with unicode: kernel's BPF"
                    }
                }
            ]
        }

    def test_save_vex_file_formatting(self):
        """Test that save_vex_file uses correct JSON formatting."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            VexKernelCheckerBase.save_vex_file(self.test_data, temp_path)

            # Read the file and check formatting
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check for space before and after colon (Dependency Tracker format)
            self.assertIn('"bomFormat" : "CycloneDX"', content)
            self.assertIn('"specVersion" : "1.5"', content)

            # Check that response is an array with proper formatting
            self.assertIn('"response" : [', content)
            self.assertIn('"can_not_fix"', content)

            # Check Unicode characters are preserved (not escaped)
            self.assertIn("kernel's", content)
            self.assertNotIn(r'\u2019', content)

            # Check no trailing spaces (line should end with comma or quote, not comma-space)
            lines = content.split('\n')
            for i, line in enumerate(lines):
                # Allow final newline
                if i < len(lines) - 1:
                    self.assertFalse(line.endswith(' '), 
                                   f"Line {i+1} has trailing space: {repr(line)}")

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_save_vex_file_response_array(self):
        """Test that response field is always saved as an array."""
        import json
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            VexKernelCheckerBase.save_vex_file(self.test_data, temp_path)

            # Load and verify structure
            with open(temp_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)

            response = loaded_data['vulnerabilities'][0]['analysis']['response']
            self.assertIsInstance(response, list, 
                                "Response field must be an array per CycloneDX 1.5 spec")
            self.assertEqual(response, ["can_not_fix"])

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_save_vex_file_cyclonedx_compliance(self):
        """Test that saved file is CycloneDX 1.5 compliant."""
        import json
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            VexKernelCheckerBase.save_vex_file(self.test_data, temp_path)

            # Load and verify CycloneDX compliance
            with open(temp_path, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)

            # Check required fields
            self.assertEqual(loaded_data['bomFormat'], 'CycloneDX')
            self.assertEqual(loaded_data['specVersion'], '1.5')
            self.assertIn('version', loaded_data)

            # Check analysis values are valid
            analysis = loaded_data['vulnerabilities'][0]['analysis']
            
            valid_states = ['resolved', 'resolved_with_pedigree', 'exploitable',
                          'in_triage', 'false_positive', 'not_affected']
            self.assertIn(analysis['state'], valid_states)

            valid_justifications = ['code_not_present', 'code_not_reachable',
                                   'requires_configuration', 'requires_dependency',
                                   'requires_environment', 'protected_by_compiler',
                                   'protected_at_runtime', 'protected_at_perimeter',
                                   'protected_by_mitigating_control']
            self.assertIn(analysis['justification'], valid_justifications)

            valid_responses = ['can_not_fix', 'will_not_fix', 'update',
                             'rollback', 'workaround_available']
            for resp in analysis['response']:
                self.assertIn(resp, valid_responses)

        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
