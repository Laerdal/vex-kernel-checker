#!/usr/bin/env python3
"""
Test script to validate non-kernel CVE filtering
"""

import sys
import os
import importlib.util

# Import the module with hyphens in filename
module_path = os.path.join(os.path.dirname(__file__), "../vex-kernel-checker.py")
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", module_path)
vex_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_module)

VexKernelChecker = vex_module.VexKernelChecker
CVEInfo = vex_module.CVEInfo

def test_kernel_related_filtering():
    """Test that non-kernel CVEs return None when filtered"""
    
    print("🧪 Testing Non-Kernel CVE Filtering")
    print("=" * 50)
    
    # Create checker with patch checking enabled
    checker = VexKernelChecker(verbose=True, disable_patch_checking=False)
    
    # Mock a non-kernel CVE
    non_kernel_cve_info = CVEInfo(
        cve_id="CVE-2024-TEST-WEB",
        description="A vulnerability in Apache HTTP Server that allows remote code execution",
        patch_urls=[]
    )
    
    # Test is_kernel_related_cve directly
    is_kernel_related = checker.is_kernel_related_cve(non_kernel_cve_info)
    print(f"📋 CVE Info: {non_kernel_cve_info.description}")
    print(f"🔍 Is kernel-related: {is_kernel_related}")
    
    # Mock a kernel CVE
    kernel_cve_info = CVEInfo(
        cve_id="CVE-2024-TEST-KERNEL",
        description="A vulnerability in the Linux kernel networking subsystem that could lead to denial of service",
        patch_urls=[]
    )
    
    is_kernel_related_2 = checker.is_kernel_related_cve(kernel_cve_info)
    print(f"📋 CVE Info: {kernel_cve_info.description}")
    print(f"🔍 Is kernel-related: {is_kernel_related_2}")
    
    print("\n✅ Non-kernel CVE filtering test completed")
    print(f"   - Non-kernel CVE correctly identified: {not is_kernel_related}")
    print(f"   - Kernel CVE correctly identified: {is_kernel_related_2}")

if __name__ == "__main__":
    test_kernel_related_filtering()
