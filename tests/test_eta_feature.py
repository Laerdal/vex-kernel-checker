#!/usr/bin/env python3
"""
Test script for ETA (Estimated Time Remaining) feature in VEX Kernel Checker
Tests both sequential and parallel processing with progress tracking and ETA display.
"""

import os
import sys
import json
import time
import tempfile
import shutil
import unittest
import importlib.util

# Import the module with hyphens in filename
module_path = os.path.join(os.path.dirname(__file__), "../vex-kernel-checker.py")
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", module_path)
if spec is None or spec.loader is None:
    raise ImportError(f"Could not load module from {module_path}")
vex_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_module)
VexKernelChecker = vex_module.VexKernelChecker


class TestETAFeature(unittest.TestCase):
    """Test ETA functionality in VEX Kernel Checker"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.test_dir = tempfile.mkdtemp(prefix="vex_eta_test_")
        print(f"Test directory: {cls.test_dir}")
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)
    
    def setUp(self):
        """Set up individual test"""
        self.checker = VexKernelChecker(verbose=True)
        
        # Create test config
        self.config_path = os.path.join(self.test_dir, "test.config")
        with open(self.config_path, 'w') as f:
            f.write("CONFIG_SECURITY=y\n")
            f.write("CONFIG_NETWORK=y\n")
            f.write("CONFIG_USB=y\n")
            f.write("CONFIG_SOUND=y\n")
            f.write("CONFIG_BLOCK=y\n")
        
        # Create test kernel source directory
        self.kernel_source_path = os.path.join(self.test_dir, "kernel_source")
        os.makedirs(self.kernel_source_path, exist_ok=True)
        
        # Create test VEX data with a reasonable number of CVEs for testing
        self.test_vex_data = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://test.example.com/vex-test-eta",
            "author": "Test Author",
            "timestamp": "2024-01-15T10:00:00Z",
            "version": 1,
            "statements": [],
            "vulnerabilities": []
        }
        
        # Add 8 test CVEs for reasonable ETA testing
        test_cves = [
            "CVE-2024-1001", "CVE-2024-1002", "CVE-2024-1003", "CVE-2024-1004",
            "CVE-2024-1005", "CVE-2024-1006", "CVE-2024-1007", "CVE-2024-1008"
        ]
        
        for cve_id in test_cves:
            self.test_vex_data["vulnerabilities"].append({
                "id": cve_id,
                "affects": {
                    "group": "test-kernel",
                    "name": "Linux Kernel",
                    "version": "6.1.0"
                }
            })
            
        self.vex_path = os.path.join(self.test_dir, "test_eta.vex.json")
        with open(self.vex_path, 'w') as f:
            json.dump(self.test_vex_data, f, indent=2)
    
    def test_format_eta_seconds(self):
        """Test ETA formatting for seconds"""
        self.assertEqual(self.checker._format_eta(30), "30s")
        self.assertEqual(self.checker._format_eta(45.7), "46s")
        self.assertEqual(self.checker._format_eta(0), "Done")
        self.assertEqual(self.checker._format_eta(-5), "Done")
    
    def test_format_eta_minutes(self):
        """Test ETA formatting for minutes and seconds"""
        self.assertEqual(self.checker._format_eta(90), "1m 30s")
        self.assertEqual(self.checker._format_eta(125), "2m 5s")
        self.assertEqual(self.checker._format_eta(3540), "59m 0s")
    
    def test_format_eta_hours(self):
        """Test ETA formatting for hours and minutes"""
        self.assertEqual(self.checker._format_eta(3600), "1h 0m")
        self.assertEqual(self.checker._format_eta(3660), "1h 1m")
        self.assertEqual(self.checker._format_eta(7290), "2h 1m")
        self.assertEqual(self.checker._format_eta(86340), "23h 59m")
    
    def test_format_eta_days(self):
        """Test ETA formatting for days, hours and minutes"""
        self.assertEqual(self.checker._format_eta(86400), "1d 0h 0m")
        self.assertEqual(self.checker._format_eta(90000), "1d 1h 0m")
        self.assertEqual(self.checker._format_eta(176400), "2d 1h 0m")
    
    def test_sequential_processing_with_eta(self):
        """Test sequential processing shows ETA progress"""
        print("\n" + "="*60)
        print("Testing Sequential Processing with ETA")
        print("="*60)
        
        # Load config
        config = self.checker.load_kernel_config(self.config_path)
        
        # Process with max_workers=1 to force sequential processing
        vex_data = self.checker.load_vex_file(self.vex_path)
        
        print("Starting sequential analysis with ETA tracking...")
        start_time = time.time()
        
        updated_vex = self.checker.update_analysis_state(
            vex_data, config, self.kernel_source_path, max_workers=1
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\nSequential processing completed in {duration:.2f} seconds")
        
        # Verify results
        self.assertIsNotNone(updated_vex)
        self.assertIn('vulnerabilities', updated_vex)
        
        # Check that some vulnerabilities were processed
        processed_count = 0
        for vuln in updated_vex['vulnerabilities']:
            if 'analysis' in vuln:
                processed_count += 1
        
        print(f"Processed {processed_count} vulnerabilities")
        self.assertGreater(processed_count, 0)
    
    def test_parallel_processing_with_eta(self):
        """Test parallel processing shows ETA progress"""
        print("\n" + "="*60)
        print("Testing Parallel Processing with ETA")
        print("="*60)
        
        # Load config
        config = self.checker.load_kernel_config(self.config_path)
        
        # Process with multiple workers for parallel processing
        vex_data = self.checker.load_vex_file(self.vex_path)
        
        print("Starting parallel analysis with ETA tracking...")
        start_time = time.time()
        
        updated_vex = self.checker.update_analysis_state(
            vex_data, config, self.kernel_source_path, max_workers=3
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\nParallel processing completed in {duration:.2f} seconds")
        
        # Verify results
        self.assertIsNotNone(updated_vex)
        self.assertIn('vulnerabilities', updated_vex)
        
        # Check that some vulnerabilities were processed
        processed_count = 0
        for vuln in updated_vex['vulnerabilities']:
            if 'analysis' in vuln:
                processed_count += 1
        
        print(f"Processed {processed_count} vulnerabilities")
        self.assertGreater(processed_count, 0)
    
    def test_update_progress_with_eta(self):
        """Test that VEX update progress shows ETA"""
        print("\n" + "="*60)
        print("Testing VEX Update Progress with ETA")
        print("="*60)
        
        # Create a VEX with many vulnerabilities that need updates
        large_vex_data = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://test.example.com/vex-test-update-eta",
            "author": "Test Author",
            "timestamp": "2024-01-15T10:00:00Z",
            "version": 1,
            "statements": [],
            "vulnerabilities": []
        }
        
        # Add 15 CVEs to trigger update progress with ETA
        for i in range(1, 16):
            large_vex_data["vulnerabilities"].append({
                "id": f"CVE-2024-200{i:02d}",
                "affects": {
                    "group": "test-kernel",
                    "name": "Linux Kernel",
                    "version": "6.1.0"
                }
            })
        
        large_vex_path = os.path.join(self.test_dir, "test_large_eta.vex.json")
        with open(large_vex_path, 'w') as f:
            json.dump(large_vex_data, f, indent=2)
        
        # Load config
        config = self.checker.load_kernel_config(self.config_path)
        
        # Process to generate update progress
        vex_data = self.checker.load_vex_file(large_vex_path)
        
        print("Starting analysis to test update progress ETA...")
        start_time = time.time()
        
        updated_vex = self.checker.update_analysis_state(
            vex_data, config, self.kernel_source_path, max_workers=2
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\nLarge VEX processing completed in {duration:.2f} seconds")
        
        # Verify results
        self.assertIsNotNone(updated_vex)
        self.assertIn('vulnerabilities', updated_vex)
        
        # Check that vulnerabilities were processed
        processed_count = 0
        for vuln in updated_vex['vulnerabilities']:
            if 'analysis' in vuln:
                processed_count += 1
        
        print(f"Processed {processed_count} vulnerabilities")
        self.assertGreater(processed_count, 0)


def main():
    """Run ETA feature tests"""
    print("VEX Kernel Checker ETA Feature Tests")
    print("=" * 60)
    
    # Run tests
    unittest.main(verbosity=2, exit=False)
    
    print("\n" + "="*60)
    print("ETA Feature Testing Complete")
    print("="*60)


if __name__ == "__main__":
    main()
