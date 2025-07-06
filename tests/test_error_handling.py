#!/usr/bin/env python3
"""
Quick test script to validate the error handling changes
"""

import sys
import os

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import importlib.util
    
    # Import the module with hyphens in filename
    module_path = os.path.join(os.path.dirname(__file__), "../vex-kernel-checker.py")
    spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from {module_path}")
    
    vex_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex_module)
    
    VexKernelChecker = vex_module.VexKernelChecker
    VulnerabilityAnalysis = vex_module.VulnerabilityAnalysis
    Response = vex_module.Response
    
    print("✅ Import successful")
    
    # Test basic initialization
    checker = VexKernelChecker(verbose=True, disable_patch_checking=True)
    print("✅ Initialization successful")
    
    # Test with a missing CVE ID
    test_cve_missing_id = {}
    result = checker.check_kernel_config(test_cve_missing_id, [], "test_kernel_source")
    print(f"Missing CVE ID result: {result}")
    
    # Test with a CVE that has an ID but no other data
    test_cve_with_id = {"id": "CVE-2024-TEST-12345"}
    result = checker.check_kernel_config(test_cve_with_id, [], "test_kernel_source")
    print(f"CVE with ID result: {result}")
    
    print("✅ Basic tests completed")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
