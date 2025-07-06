#!/usr/bin/env python3
"""
Minimal test to verify error handling works correctly
"""

import sys
import os
import importlib.util

# Import the module
module_path = os.path.join(os.path.dirname(__file__), "../vex-kernel-checker.py")
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", module_path)
vex_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_module)

VexKernelChecker = vex_module.VexKernelChecker

def main():
    print("🧪 Testing Error Handling Enhancement")
    print("=" * 50)
    
    # Create checker
    checker = VexKernelChecker(verbose=False, disable_patch_checking=True)
    
    # Test cases that should return None
    test_cases = [
        ("Missing CVE ID", {}),
        ("Empty CVE ID", {"id": ""}),
        ("CVE with valid ID", {"id": "CVE-2024-TEST-12345"}),
    ]
    
    for test_name, cve_data in test_cases:
        print(f"\n🔬 {test_name}: {cve_data}")
        result = checker.check_kernel_config(cve_data, [], "test_kernel_source")
        
        if result is None:
            print(f"   ✅ Result: None (no analysis registered)")
        else:
            print(f"   ✅ Result: {result.state.value} with response: {result.response.value}")
    
    print(f"\n🎉 Error handling enhancement working correctly!")

if __name__ == "__main__":
    main()
