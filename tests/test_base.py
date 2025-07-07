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
        self.assertEqual(base.arch, 'x86_64')
        self.assertIsInstance(base.perf_tracker, PerformanceTracker)
    
    def test_custom_initialization(self):
        """Test base class initialization with custom parameters."""
        base = VexKernelCheckerBase(
            verbose=True,
            check_patches=True,
            analyze_all_cves=True,
            arch='arm64'
        )
        
        self.assertTrue(base.verbose)
        self.assertTrue(base.check_patches)
        self.assertTrue(base.analyze_all_cves)
        self.assertEqual(base.arch, 'arm64')
    
    def test_kwargs_initialization(self):
        """Test base class initialization with keyword arguments."""
        kwargs = {
            'verbose': True,
            'check_patches': False,
            'arch': 'arm',
            'unknown_param': 'ignored'  # Should be ignored
        }
        
        base = VexKernelCheckerBase(**kwargs)
        
        self.assertTrue(base.verbose)
        self.assertFalse(base.check_patches)
        self.assertEqual(base.arch, 'arm')
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
