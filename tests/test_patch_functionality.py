#!/usr/bin/env python3
"""
Test patch fetching functionality directly to see if it's working.
"""

import sys
import os
import json

# Add current directory to Python path
sys.path.insert(0, '.')

try:
    # Import the VexKernelChecker from the fresh file
    import importlib.util
    spec = importlib.util.spec_from_file_location("vex_kernel_checker", "../vex-kernel-checker.py")
    vex_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex_module)
    
    VexKernelChecker = vex_module.VexKernelChecker
    CVEInfo = vex_module.CVEInfo
    
except ImportError as e:
    print(f"Failed to import VexKernelChecker: {e}")
    sys.exit(1)

def test_patch_url_extraction():
    """Test if we can extract patch URLs from CVE data."""
    print("=== Testing Patch URL Extraction ===")
    
    checker = VexKernelChecker(verbose=True)
    
    # Test with a sample CVE that should have patch info
    test_cve = {
        "id": "CVE-2023-1234",
        "description": "Test CVE with patch info",
        "references": [
            {"url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abc123def456"},
            {"url": "https://github.com/torvalds/linux/commit/abc123def456"},
            {"url": "https://lore.kernel.org/some-list/message.html"}
        ]
    }
    
    # Create CVEInfo object
    cve_info = CVEInfo(
        cve_id=test_cve["id"],
        description=test_cve.get("description", ""),
        references=test_cve.get("references", [])
    )
    
    # Test patch URL extraction
    patch_url = checker.extract_patch_url(cve_info)
    print(f"Extracted patch URL: {patch_url}")
    
    if patch_url:
        print("✅ Patch URL extraction working")
        return patch_url
    else:
        print("❌ Patch URL extraction failed")
        return None

def test_commit_id_extraction():
    """Test commit ID extraction from URLs."""
    print("\n=== Testing Commit ID Extraction ===")
    
    checker = VexKernelChecker(verbose=True)
    
    test_urls = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abc123def456",
        "https://github.com/torvalds/linux/commit/abc123def456",
        "https://lore.kernel.org/all/abc123def456.patch"
    ]
    
    for url in test_urls:
        commit_id = checker._extract_commit_id_from_url(url)
        print(f"URL: {url}")
        print(f"Commit ID: {commit_id}")
        print()

def test_github_patch_fetch():
    """Test GitHub patch fetching with a real commit."""
    print("=== Testing GitHub Patch Fetch ===")
    
    # Use a real commit ID from Linux kernel
    real_commit_id = "6450e94b31557f56c5b9a4b2eb7c79d30721ea15"  # Random real commit
    
    print(f"Testing with real commit ID: {real_commit_id}")
    
    try:
        patch_content = VexKernelChecker.fetch_patch_from_github(real_commit_id)
        
        if patch_content:
            print(f"✅ GitHub patch fetch successful")
            print(f"Patch size: {len(patch_content)} characters")
            print(f"First 200 chars: {patch_content[:200]}...")
            return True
        else:
            print("❌ GitHub patch fetch failed - no content returned")
            return False
            
    except Exception as e:
        print(f"❌ GitHub patch fetch failed with error: {e}")
        return False

def test_http_patch_fetch():
    """Test HTTP patch fetching."""
    print("\n=== Testing HTTP Patch Fetch ===")
    
    checker = VexKernelChecker(verbose=True)
    
    # Test with a GitHub patch URL (should work via HTTP)
    test_url = "https://github.com/torvalds/linux/commit/6450e94b31557f56c5b9a4b2eb7c79d30721ea15.patch"
    
    print(f"Testing HTTP fetch with URL: {test_url}")
    
    try:
        patch_content = checker.fetch_patch_content_with_github_priority(test_url)
        
        if patch_content:
            print(f"✅ HTTP patch fetch successful")
            print(f"Patch size: {len(patch_content)} characters")
            print(f"First 200 chars: {patch_content[:200]}...")
            return True
        else:
            print("❌ HTTP patch fetch failed - no content returned")
            return False
            
    except Exception as e:
        print(f"❌ HTTP patch fetch failed with error: {e}")
        return False

def test_real_cve_analysis():
    """Test with a real CVE that has patch information."""
    print("\n=== Testing Real CVE Analysis ===")
    
    # Load a test VEX file that should have CVEs with patch info
    vex_files = [
        "examples/test_real_cve.json",
        "examples/test_kernel_cve.json", 
        "test.json"
    ]
    
    vex_data = None
    for vex_file in vex_files:
        if os.path.exists(vex_file):
            try:
                with open(vex_file, 'r') as f:
                    vex_data = json.load(f)
                print(f"Loaded VEX data from: {vex_file}")
                break
            except Exception as e:
                print(f"Failed to load {vex_file}: {e}")
                continue
    
    if not vex_data:
        print("❌ No VEX test data found")
        return False
    
    # Get first few CVEs
    vulnerabilities = vex_data.get('vulnerabilities', [])[:3]  # Test first 3
    
    if not vulnerabilities:
        print("❌ No vulnerabilities found in VEX data")
        return False
    
    print(f"Testing with {len(vulnerabilities)} CVEs...")
    
    checker = VexKernelChecker(verbose=True, check_patches=True)
    
    patch_found_count = 0
    for vuln in vulnerabilities:
        cve_id = vuln.get('id', 'unknown')
        print(f"\nTesting CVE: {cve_id}")
        
        # Create CVEInfo from vulnerability data
        cve_info = CVEInfo(
            cve_id=cve_id,
            description=vuln.get('description', ''),
            references=vuln.get('references', [])
        )
        
        # Test patch URL extraction
        patch_url = checker.extract_patch_url(cve_info)
        if patch_url:
            print(f"  ✅ Found patch URL: {patch_url[:100]}...")
            
            # Test patch content fetch
            patch_content = checker.fetch_patch_content_with_github_priority(patch_url)
            if patch_content:
                print(f"  ✅ Fetched patch content: {len(patch_content)} chars")
                patch_found_count += 1
            else:
                print(f"  ❌ Failed to fetch patch content")
        else:
            print(f"  ❌ No patch URL found")
    
    print(f"\nSummary: Found patches for {patch_found_count}/{len(vulnerabilities)} CVEs")
    return patch_found_count > 0

def main():
    """Run all patch functionality tests."""
    print("VEX Kernel Checker - Patch Functionality Test")
    print("=" * 50)
    
    results = []
    
    # Test 1: Patch URL extraction
    try:
        patch_url = test_patch_url_extraction()
        results.append(("Patch URL Extraction", patch_url is not None))
    except Exception as e:
        print(f"❌ Patch URL extraction test failed: {e}")
        results.append(("Patch URL Extraction", False))
    
    # Test 2: Commit ID extraction  
    try:
        test_commit_id_extraction()
        results.append(("Commit ID Extraction", True))
    except Exception as e:
        print(f"❌ Commit ID extraction test failed: {e}")
        results.append(("Commit ID Extraction", False))
    
    # Test 3: GitHub patch fetch
    try:
        github_success = test_github_patch_fetch()
        results.append(("GitHub Patch Fetch", github_success))
    except Exception as e:
        print(f"❌ GitHub patch fetch test failed: {e}")
        results.append(("GitHub Patch Fetch", False))
    
    # Test 4: HTTP patch fetch
    try:
        http_success = test_http_patch_fetch()
        results.append(("HTTP Patch Fetch", http_success))
    except Exception as e:
        print(f"❌ HTTP patch fetch test failed: {e}")
        results.append(("HTTP Patch Fetch", False))
    
    # Test 5: Real CVE analysis
    try:
        real_cve_success = test_real_cve_analysis()
        results.append(("Real CVE Analysis", real_cve_success))
    except Exception as e:
        print(f"❌ Real CVE analysis test failed: {e}")
        results.append(("Real CVE Analysis", False))
    
    # Summary
    print("\n" + "=" * 50)
    print("PATCH FUNCTIONALITY TEST SUMMARY")
    print("=" * 50)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{test_name:<25} {status}")
    
    total_tests = len(results)
    passed_tests = sum(1 for _, success in results if success)
    
    print(f"\nOverall: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 All patch functionality tests passed!")
        return 0
    else:
        print("⚠️  Some patch functionality tests failed!")
        print("This may explain why patch-based analysis isn't working correctly.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
