#!/usr/bin/env python3
"""
Test script for Response field implementation in VEX Kernel Checker
Tests that all VulnerabilityAnalysis instances include the proper response field.
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
module_path = os.path.join(os.path.dirname(__file__), "..", "vex-kernel-checker.py")
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", module_path)
if spec is None or spec.loader is None:
    raise ImportError(f"Could not load module from {module_path}")
vex_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_module)
VexKernelChecker = vex_module.VexKernelChecker
Response = vex_module.Response
VulnerabilityState = vex_module.VulnerabilityState
Justification = vex_module.Justification
VulnerabilityAnalysis = vex_module.VulnerabilityAnalysis


class TestResponseField(unittest.TestCase):
    """Test Response field in VulnerabilityAnalysis"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        cls.test_dir = tempfile.mkdtemp(prefix="vex_response_test_")
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
        
        # Create test kernel source directory
        self.kernel_source_path = os.path.join(self.test_dir, "kernel_source")
        os.makedirs(self.kernel_source_path, exist_ok=True)
    
    def test_response_enum_values(self):
        """Test that Response enum has all expected values"""
        expected_values = [
            "can_not_fix",
            "will_not_fix", 
            "update",
            "rollback",
            "workaround_available"
        ]
        
        actual_values = [r.value for r in Response]
        print(f"Response enum values: {actual_values}")
        
        for expected in expected_values:
            self.assertIn(expected, actual_values, f"Missing response value: {expected}")
    
    def test_vulnerability_analysis_with_response(self):
        """Test that VulnerabilityAnalysis includes response field in output"""
        
        analysis = VulnerabilityAnalysis(
            state=VulnerabilityState.NOT_AFFECTED,
            justification=Justification.COMPONENT_NOT_PRESENT,
            response=Response.WILL_NOT_FIX,
            detail="Test analysis",
            timestamp="2024-01-01T00:00:00Z"
        )
        
        result_dict = analysis.to_dict()
        print(f"Analysis dict: {result_dict}")
        
        # Verify all fields are present
        self.assertIn("state", result_dict)
        self.assertIn("justification", result_dict)
        self.assertIn("response", result_dict)
        self.assertIn("detail", result_dict)
        self.assertIn("timestamp", result_dict)
        
        # Verify values
        self.assertEqual(result_dict["state"], "not_affected")
        self.assertEqual(result_dict["justification"], "component_not_present")
        self.assertEqual(result_dict["response"], "will_not_fix")
        self.assertEqual(result_dict["detail"], "Test analysis")
    
    def test_response_field_in_real_analysis(self):
        """Test that response field appears in real CVE analysis"""
        # Create a simple test VEX with a CVE
        test_vex_data = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": "https://test.example.com/vex-test-response",
            "author": "Test Author",
            "timestamp": "2024-01-15T10:00:00Z",
            "version": 1,
            "statements": [],
            "vulnerabilities": [
                {
                    "id": "CVE-2024-9999",
                    "affects": {
                        "group": "test-kernel",
                        "name": "Linux Kernel",
                        "version": "6.1.0"
                    }
                }
            ]
        }
        
        vex_path = os.path.join(self.test_dir, "test_response.vex.json")
        with open(vex_path, 'w') as f:
            json.dump(test_vex_data, f, indent=2)
        
        # Load config
        config = self.checker.load_kernel_config(self.config_path)
        
        # Process the VEX data
        print("Processing VEX data to test response field...")
        vex_data = self.checker.load_vex_file(vex_path)
        
        # Analyze one CVE
        cve = vex_data['vulnerabilities'][0]
        analysis = self.checker.check_kernel_config(cve, config, self.kernel_source_path)
        
        # Check that analysis has response field (if analysis was returned)
        if analysis is not None:
            self.assertIsNotNone(analysis.response, "Analysis should have a response field")
            print(f"Analysis response: {analysis.response.value}")
            
            # Convert to dict and check response is included
            analysis_dict = analysis.to_dict()
            self.assertIn("response", analysis_dict, "Analysis dict should include response field")
            print(f"Analysis dict response: {analysis_dict['response']}")
        else:
            print("Analysis returned None (CVE filtered out or error occurred)")
    
    def test_different_response_scenarios(self):
        """Test different scenarios produce appropriate response values"""
        config = self.checker.load_kernel_config(self.config_path)
        
        # Test CVE with missing ID
        missing_id_cve = {}
        analysis = self.checker.check_kernel_config(missing_id_cve, config, self.kernel_source_path)
        self.assertIsNone(analysis, "Missing CVE ID should return None (no analysis outcome)")
        print(f"Missing ID scenario - Response: None (no analysis registered)")
        
        # Test CVE that will be processed (fake CVE that won't be found)
        fake_cve = {"id": "CVE-2024-99999"}
        analysis = self.checker.check_kernel_config(fake_cve, config, self.kernel_source_path)
        # This should either return a proper analysis or None if CVE fetch fails
        if analysis is not None:
            self.assertIsNotNone(analysis.response, "Valid analysis should have a response field") 
            print(f"Fake CVE scenario - Response: {analysis.response.value}")
        else:
            print(f"Fake CVE scenario - Response: None (CVE fetch failed, no analysis registered)")
    
    def test_all_response_values_used(self):
        """Test that the tool can produce all different response values"""
        response_values_found = set()
        
        # Test scenarios that should produce different responses
        config = self.checker.load_kernel_config(self.config_path)
        
        test_scenarios = [
            {"id": ""},  # Missing ID
            {"id": "CVE-2024-99998"},  # Non-existent CVE
            {},  # No ID field
        ]
        
        for i, scenario in enumerate(test_scenarios):
            print(f"Testing scenario {i+1}: {scenario}")
            analysis = self.checker.check_kernel_config(scenario, config, self.kernel_source_path)
            if analysis is not None and analysis.response:
                response_values_found.add(analysis.response.value)
                print(f"  Response: {analysis.response.value}")
            else:
                print(f"  Response: None (no analysis registered)")
        
        print(f"Response values found in testing: {response_values_found}")
        
        # At minimum we should find some response values
        self.assertGreater(len(response_values_found), 0, "Should find at least one response value")


def main():
    """Run Response field tests"""
    print("VEX Kernel Checker Response Field Tests")
    print("=" * 60)
    
    # Run tests
    unittest.main(verbosity=2, exit=False)
    
    print("\n" + "="*60)
    print("Response Field Testing Complete")
    print("="*60)


if __name__ == "__main__":
    main()
