#!/usr/bin/env python3
"""
Test script to validate patch fetching functionality in VEX Kernel Checker.
This will test all the patch fetching methods and demonstrate their capabilities.
"""

import json
import sys
import time
import os

# Add current directory to path to import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import by renaming the file in the import
import importlib.util
spec = importlib.util.spec_from_file_location("vex_kernel_checker", "../vex-kernel-checker.py")
if spec is not None and spec.loader is not None:
    vex_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex_module)
    VexKernelChecker = vex_module.VexKernelChecker
else:
    raise ImportError("Could not load vex-kernel-checker.py")

def test_patch_url_extraction():
    """Test patch URL extraction from CVE data."""
    print("=" * 60)
    print("Testing Patch URL Extraction")
    print("=" * 60)
    
    checker = VexKernelChecker(verbose=True)
    
    # Test with a known CVE that should have patch URLs
    test_cves = [
        "CVE-2023-52340",  # Recent kernel CVE
        "CVE-2023-45863",  # Another kernel CVE
        "CVE-2023-1073",   # Older kernel CVE
    ]
    
    for cve_id in test_cves:
        print(f"\n--- Testing {cve_id} ---")
        
        # Fetch CVE details
        cve_info = checker.fetch_cve_details(cve_id)
        if not cve_info:
            print(f"❌ Failed to fetch CVE details for {cve_id}")
            continue
            
        print(f"✓ Fetched CVE details for {cve_id}")
        print(f"  Description: {cve_info.description[:100]}...")
        print(f"  CVSS Score: {cve_info.cvss_score}")
        print(f"  Severity: {cve_info.severity}")
        print(f"  Found {len(cve_info.patch_urls)} patch URLs")
        
        for i, url in enumerate(cve_info.patch_urls):
            print(f"    {i+1}. {url}")
        
        # Test patch URL extraction
        best_patch_url = checker.extract_patch_url(cve_info)
        if best_patch_url:
            print(f"✓ Best patch URL: {best_patch_url}")
            
            # Test commit ID extraction
            commit_id = checker._extract_commit_id_from_url(best_patch_url)
            print(f"✓ Extracted commit ID: {commit_id}")
            
            # Test alternative URL generation
            alternatives = checker.get_alternative_patch_urls(best_patch_url)
            print(f"✓ Generated {len(alternatives)} alternative URLs:")
            for alt in alternatives[:3]:  # Show first 3
                print(f"    - {alt}")
        else:
            print("❌ No suitable patch URL found")
        
        print("-" * 40)

def test_commit_id_extraction():
    """Test commit ID extraction from various URL formats."""
    print("\n" + "=" * 60)
    print("Testing Commit ID Extraction")
    print("=" * 60)
    
    checker = VexKernelChecker(verbose=True)
    
    test_urls = [
        "https://github.com/torvalds/linux/commit/abc123def456",
        "https://github.com/torvalds/linux/commit/abc123def456.patch",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=abc123def456",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=abc123def456",
        "https://lore.kernel.org/linux-kernel/abc123def456",
        "https://invalid-url-format.com/no-commit-id",
    ]
    
    for url in test_urls:
        commit_id = checker._extract_commit_id_from_url(url)
        status = "✓" if commit_id else "❌"
        print(f"{status} {url}")
        if commit_id:
            print(f"    → Commit ID: {commit_id}")

def test_patch_content_fetching():
    """Test patch content fetching with real URLs."""
    print("\n" + "=" * 60)
    print("Testing Patch Content Fetching")
    print("=" * 60)
    
    checker = VexKernelChecker(verbose=True)
    
    # Test URLs - using real kernel commits that should exist
    test_urls = [
        "https://github.com/torvalds/linux/commit/6e65afe6cd53d4ad5c63ba1ef190098d4002760a.patch",
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=6e65afe6cd53d4ad5c63ba1ef190098d4002760a",
    ]
    
    for url in test_urls:
        print(f"\n--- Testing patch fetch from: {url} ---")
        
        start_time = time.time()
        patch_content = checker.fetch_patch_content_with_github_priority(url)
        fetch_time = time.time() - start_time
        
        if patch_content:
            print(f"✓ Successfully fetched patch content in {fetch_time:.2f}s")
            print(f"  Content length: {len(patch_content)} characters")
            
            # Check for patch indicators
            indicators = ['diff --git', 'index ', '@@', '+++', '---']
            found_indicators = [ind for ind in indicators if ind in patch_content]
            print(f"  Found patch indicators: {found_indicators}")
            
            # Extract source files from patch
            source_files = checker.extract_sourcefiles(patch_content)
            print(f"  Extracted {len(source_files)} source files:")
            for sf in list(source_files)[:5]:  # Show first 5
                print(f"    - {sf}")
                
        else:
            print(f"❌ Failed to fetch patch content in {fetch_time:.2f}s")

def test_github_api_fetching():
    """Test GitHub API patch fetching specifically."""
    print("\n" + "=" * 60)
    print("Testing GitHub API Patch Fetching")
    print("=" * 60)
    
    # Test with a real commit ID
    test_commit_ids = [
        "6e65afe6cd53d4ad5c63ba1ef190098d4002760a",  # Real kernel commit
        "abc123def456789",  # Fake commit ID to test error handling
    ]
    
    for commit_id in test_commit_ids:
        print(f"\n--- Testing GitHub API with commit: {commit_id} ---")
        
        start_time = time.time()
        patch_content = VexKernelChecker.fetch_patch_from_github(commit_id)
        fetch_time = time.time() - start_time
        
        if patch_content:
            print(f"✓ Successfully fetched from GitHub API in {fetch_time:.2f}s")
            print(f"  Content length: {len(patch_content)} characters")
            
            # Show first few lines
            lines = patch_content.split('\n')[:5]
            for line in lines:
                print(f"    {line}")
        else:
            print(f"❌ Failed to fetch from GitHub API in {fetch_time:.2f}s")

def test_with_real_vex_data():
    """Test patch fetching with real VEX data from test files."""
    print("\n" + "=" * 60)
    print("Testing with Real VEX Data")
    print("=" * 60)
    
    checker = VexKernelChecker(verbose=True, check_patches=True)
    
    # Look for test VEX files with real CVE data
    test_files = [
        "examples/test_small_vex.json",
        "examples/test_kernel_cve.json",
        "examples/test_real_cve.json",
    ]
    
    for test_file in test_files:
        try:
            print(f"\n--- Testing with {test_file} ---")
            
            with open(test_file, 'r') as f:
                vex_data = json.load(f)
            
            # Find first CVE in the VEX data
            vulnerabilities = vex_data.get('vulnerabilities', [])
            if not vulnerabilities:
                print(f"❌ No vulnerabilities found in {test_file}")
                continue
                
            first_vuln = vulnerabilities[0]
            cve_id = first_vuln.get('cve')
            if not cve_id:
                print(f"❌ No CVE ID found in first vulnerability")
                continue
                
            print(f"✓ Found CVE: {cve_id}")
            
            # Fetch CVE details and try patch fetching
            cve_info = checker.fetch_cve_details(cve_id)
            if cve_info and cve_info.patch_urls:
                print(f"✓ Found {len(cve_info.patch_urls)} patch URLs")
                
                # Try fetching the first patch
                best_url = checker.extract_patch_url(cve_info)
                if best_url:
                    print(f"✓ Best patch URL: {best_url}")
                    
                    patch_content = checker.fetch_patch_content_with_github_priority(best_url)
                    if patch_content:
                        print(f"✓ Successfully fetched patch content ({len(patch_content)} chars)")
                        
                        # Extract source files
                        source_files = checker.extract_sourcefiles(patch_content)
                        print(f"✓ Extracted {len(source_files)} source files")
                    else:
                        print("❌ Failed to fetch patch content")
                else:
                    print("❌ No suitable patch URL found")
            else:
                print("❌ No patch URLs found in CVE details")
                
        except FileNotFoundError:
            print(f"❌ Test file not found: {test_file}")
        except Exception as e:
            print(f"❌ Error processing {test_file}: {e}")

def main():
    """Run all patch fetching tests."""
    print("VEX Kernel Checker - Patch Fetching Test Suite")
    print("=" * 60)
    
    try:
        # Test 1: Patch URL extraction from CVE data
        test_patch_url_extraction()
        
        # Test 2: Commit ID extraction from URLs
        test_commit_id_extraction()
        
        # Test 3: Patch content fetching
        test_patch_content_fetching()
        
        # Test 4: GitHub API fetching
        test_github_api_fetching()
        
        # Test 5: Real VEX data
        test_with_real_vex_data()
        
        print("\n" + "=" * 60)
        print("Patch Fetching Test Suite Complete")
        print("=" * 60)
        
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
    except Exception as e:
        print(f"\n\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
