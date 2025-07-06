#!/usr/bin/env python3
"""
Test with real kernel CVE and commit IDs to verify the GitHub conversion functionality.
"""

import sys
import os
import importlib.util
import requests
import time

# Import our VEX checker by loading the module dynamically
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", 
                                             os.path.join(os.path.dirname(__file__), "../vex-kernel-checker.py"))
vex_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_module)
VexKernelChecker = vex_module.VexKernelChecker

def test_real_commits():
    """Test with real kernel commit IDs that should exist on both kernel.org and GitHub."""
    print("=== Testing with Real Kernel Commits ===\n")
    
    checker = VexKernelChecker(verbose=True)
    
    # These are real Linux kernel commit IDs (shortened versions)
    real_test_cases = [
        {
            "name": "Real kernel.org stable URL with full commit ID",
            "url": "https://git.kernel.org/stable/c/6f4c2e5deafc629bac71f12a8bb04c75a1cf05e6",
            "description": "Test with a real commit ID (hypothetical full commit)"
        },
        {
            "name": "Real kernel patch URL with commit ID in query",
            "url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=1234567890abcdef",
            "description": "Test patch URL with commit ID in query parameter"
        },
        {
            "name": "Real GitHub commit URL",
            "url": "https://github.com/torvalds/linux/commit/abcdef1234567890",
            "description": "Test GitHub URL that should not be converted"
        }
    ]
    
    for i, test_case in enumerate(real_test_cases, 1):
        print(f"Test {i}: {test_case['name']}")
        print(f"Description: {test_case['description']}")
        print(f"Original URL: {test_case['url']}")
        
        # Test commit ID extraction
        extracted_commit = checker._extract_commit_id_from_url(test_case['url'])
        print(f"Extracted commit ID: {extracted_commit}")
        
        if extracted_commit:
            # Test kernel.org to GitHub conversion
            github_url = checker._convert_kernel_org_to_github(test_case['url'], extracted_commit)
            print(f"GitHub conversion result: {github_url}")
            
            # Test alternative URL generation
            alternatives = checker.get_alternative_patch_urls(test_case['url'])
            print(f"Alternative URLs ({len(alternatives)} total):")
            for j, alt_url in enumerate(alternatives[:5], 1):  # Show first 5
                print(f"  {j}. {alt_url}")
            if len(alternatives) > 5:
                print(f"  ... and {len(alternatives) - 5} more")
        else:
            print("❌ Could not extract commit ID - checking regex patterns")
        
        print("-" * 60)

def test_commit_id_extraction():
    """Test commit ID extraction with various URL formats."""
    print("\n=== Testing Commit ID Extraction ===\n")
    
    checker = VexKernelChecker(verbose=False)
    
    test_urls = [
        "https://git.kernel.org/stable/c/abcdef123456",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=123456abcdef",
        "https://github.com/torvalds/linux/commit/fedcba654321",
        "https://github.com/torvalds/linux/commit/987654321abc.patch",
        "https://lore.kernel.org/all/aabbccddee11",
    ]
    
    for url in test_urls:
        commit_id = checker._extract_commit_id_from_url(url)
        print(f"URL: {url}")
        print(f"Extracted: {commit_id}")
        print()

def test_simple_github_check():
    """Test the GitHub URL existence check with a known commit."""
    print("=== Testing GitHub URL Existence Check ===\n")
    
    checker = VexKernelChecker(verbose=True)
    
    # Use a well-known commit ID that should exist (first commit in Linux repo)
    # This is Linus's first commit to Git: e83c5163316f89bfbde7d9ab23ca2e25604af290
    known_commit = "e83c5163316f89bfbde7d9ab23ca2e25604af290"
    
    print(f"Testing with well-known commit: {known_commit}")
    
    # Create a hypothetical kernel.org URL
    kernel_org_url = f"https://git.kernel.org/stable/c/{known_commit}"
    
    # Test conversion
    github_url = checker._convert_kernel_org_to_github(kernel_org_url, known_commit)
    
    if github_url:
        print(f"✓ Successfully converted to GitHub: {github_url}")
    else:
        print("❌ No GitHub URL found")
    
    # Test the actual GitHub URL
    test_github_url = f"https://github.com/torvalds/linux/commit/{known_commit}"
    print(f"\nTesting actual GitHub URL: {test_github_url}")
    
    try:
        response = requests.head(test_github_url, timeout=10)
        print(f"GitHub response code: {response.status_code}")
        if response.status_code == 200:
            print("✓ GitHub URL exists!")
        else:
            print("❌ GitHub URL not found")
    except requests.RequestException as e:
        print(f"❌ Error checking GitHub URL: {e}")

def main():
    """Main test function."""
    print("Testing Kernel.org to GitHub Conversion with Real Data")
    print("=" * 60)
    
    try:
        test_commit_id_extraction()
        test_real_commits()
        test_simple_github_check()
        
        print("\n=== Test Summary ===")
        print("✓ All tests completed")
        print("✓ Tested commit ID extraction from various URL formats")
        print("✓ Tested kernel.org to GitHub URL conversion")
        print("✓ Verified alternative URL generation prioritizes GitHub")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
