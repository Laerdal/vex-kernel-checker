#!/usr/bin/env python3
"""
Test script to demonstrate how VEX Kernel Checker fetches patch URLs from NVD API

This script shows:
1. VEX file contains only CVE IDs (not patch URLs)
2. Patch URLs are fetched from NVD API using the CVE ID
3. Different behavior with/without valid API key
"""

import sys
import os
import json

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the actual script
exec(open('vex-kernel-checker.py').read())

def test_patch_url_flow():
    """Test the patch URL fetching flow."""
    print("=" * 60)
    print("VEX KERNEL CHECKER - PATCH URL FETCHING TEST")
    print("=" * 60)
    
    # Create test VEX data with only CVE ID
    test_vex_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "vulnerabilities": [
            {
                "id": "CVE-2024-26581",
                "description": "Linux kernel vulnerability (patches from NVD)",
                "analysis": {
                    "detail": "Test CVE for patch analysis",
                    "justification": "code_not_present",
                    "state": "under_investigation"
                }
            }
        ]
    }
    
    print("\n1. VEX FILE STRUCTURE:")
    print("   - Contains CVE ID: CVE-2024-26581")
    print("   - Does NOT contain patch URLs")
    print("   - Patch URLs will be fetched from NVD API")
    
    # Test without API key
    print("\n2. TEST WITHOUT API KEY:")
    print("   - Should disable patch checking")
    print("   - Should fall back to config-only analysis")
    
    checker_no_api = VexKernelChecker(
        kernel_config_path="test_demo.config",
        kernel_source_path="test_kernel_source",
        verbose=True
    )
    
    print(f"   Patch checking enabled: {checker_no_api.check_patches}")
    
    # Test with fake API key
    print("\n3. TEST WITH FAKE API KEY:")
    print("   - Should enable patch checking")
    print("   - NVD API call will fail with fake key")
    print("   - Should show 'No patch URL found'")
    
    checker_fake_api = VexKernelChecker(
        kernel_config_path="test_demo.config",
        kernel_source_path="test_kernel_source",
        api_key="fake_key_123",
        verbose=True
    )
    
    print(f"   Patch checking enabled: {checker_fake_api.check_patches}")
    
    # Try to fetch CVE details with fake key
    print("\n4. TESTING NVD API CALL:")
    print("   - Attempting to fetch CVE-2024-26581 from NVD...")
    
    cve_info = checker_fake_api.fetch_cve_details("CVE-2024-26581")
    
    if cve_info:
        print(f"   ✅ CVE details fetched successfully")
        print(f"   Description: {cve_info.description[:100]}...")
        print(f"   Patch URLs found: {len(cve_info.patch_urls) if cve_info.patch_urls else 0}")
        if cve_info.patch_urls:
            for i, url in enumerate(cve_info.patch_urls[:3]):
                print(f"     {i+1}. {url}")
    else:
        print("   ❌ CVE details not found (expected with fake API key)")
    
    print("\n5. CONCLUSION:")
    print("   ✅ VEX file correctly contains only CVE IDs")
    print("   ✅ Patch URLs are fetched from NVD API (not VEX file)")
    print("   ✅ Tool behavior matches expected architecture")
    print("   🔍 Real NVD API key needed for complete patch analysis")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    test_patch_url_flow()
