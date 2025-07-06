#!/usr/bin/env python3
"""
Test suite for filesystem vulnerability analysis in VEX Kernel Checker.

This script tests the SMB/CIFS, NFS, EXT4, and BTRFS filesystem pattern detection
and configuration analysis capabilities that were added to the kernel checker.

Tests include:
- SMB/CIFS pattern detection and config analysis
- NFS pattern detection and config analysis  
- Mixed filesystem environment testing
- Proper "exploitable" vs "not_affected" classification

Usage:
    python3 test_filesystem_analysis.py
    
Or run individual tests:
    python3 test_filesystem_analysis.py --test smb
    python3 test_filesystem_analysis.py --test nfs
    python3 test_filesystem_analysis.py --test mixed
"""

import os
import sys
import subprocess
import argparse
import json
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def run_vex_checker(vex_file, config_file, test_name):
    """Run the VEX kernel checker with given files."""
    cmd = [
        sys.executable, "../vex-kernel-checker.py",
        "--vex-file", vex_file,
        "--kernel-config", config_file, 
        "--kernel-source", "../test_kernel_source",
        "--verbose", "--config-only", "--reanalyse"
    ]
    
    print(f"\n{'='*60}")
    print(f"🧪 RUNNING TEST: {test_name}")
    print(f"{'='*60}")
    print(f"Command: {' '.join(cmd)}")
    print(f"VEX file: {vex_file}")
    print(f"Config file: {config_file}")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=Path(__file__).parent)
        
        print("STDOUT:")
        print(result.stdout)
        
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        if result.returncode != 0:
            print(f"❌ Test failed with return code {result.returncode}")
            return False
        else:
            print(f"✅ Test completed successfully")
            return True
            
    except Exception as e:
        print(f"❌ Error running test: {e}")
        return False

def verify_vex_results(vex_file, expected_results):
    """Verify the VEX file contains expected analysis results."""
    try:
        with open(vex_file, 'r') as f:
            vex_data = json.load(f)
        
        print(f"\n🔍 VERIFYING RESULTS: {vex_file}")
        print(f"Expected: {expected_results}")
        
        actual_results = {}
        for vuln in vex_data.get('vulnerabilities', []):
            cve_id = vuln.get('id')
            if 'analysis' in vuln:
                state = vuln['analysis'].get('state')
                detail = vuln['analysis'].get('detail', '')
                actual_results[cve_id] = {'state': state, 'detail': detail}
        
        print(f"Actual: {actual_results}")
        
        all_correct = True
        for cve_id, expected in expected_results.items():
            if cve_id not in actual_results:
                print(f"❌ Missing analysis for {cve_id}")
                all_correct = False
            elif actual_results[cve_id]['state'] != expected['state']:
                print(f"❌ Wrong state for {cve_id}: expected {expected['state']}, got {actual_results[cve_id]['state']}")
                all_correct = False
            else:
                print(f"✅ Correct result for {cve_id}: {expected['state']}")
        
        return all_correct
        
    except Exception as e:
        print(f"❌ Error verifying results: {e}")
        return False

def test_smb_with_cifs():
    """Test SMB CVE with CIFS enabled - should be exploitable."""
    success = run_vex_checker("test_smb_cve.json", "test_smb.config", "SMB with CIFS enabled")
    if success:
        expected = {
            "CVE-2023-52757": {"state": "exploitable"}
        }
        return verify_vex_results("test_smb_cve.json", expected)
    return False

def test_smb_without_cifs():
    """Test SMB CVE without CIFS enabled - should be not_affected."""
    success = run_vex_checker("test_smb_cve.json", "test_no_smb.config", "SMB without CIFS enabled")
    if success:
        expected = {
            "CVE-2023-52757": {"state": "not_affected"}
        }
        return verify_vex_results("test_smb_cve.json", expected)
    return False

def test_nfs_without_support():
    """Test NFS CVE without NFS support - should be not_affected."""
    success = run_vex_checker("test_nfs_cve.json", "test_no_nfs.config", "NFS without support")
    if success:
        expected = {
            "CVE-2024-TEST-NFS": {"state": "not_affected"}
        }
        return verify_vex_results("test_nfs_cve.json", expected)
    return False

def test_mixed_filesystems():
    """Test multiple filesystem CVEs with mixed support."""
    success = run_vex_checker("test_fs_multi.json", "test_mixed_fs.config", "Mixed filesystem support")
    if success:
        expected = {
            "CVE-2024-TEST-SMB": {"state": "not_affected"},   # CIFS not enabled
            "CVE-2024-TEST-NFS": {"state": "not_affected"},   # NFS not enabled
            "CVE-2024-TEST-EXT4": {"state": "exploitable"},   # EXT4 enabled
            "CVE-2024-TEST-BTRFS": {"state": "exploitable"}   # BTRFS enabled
        }
        return verify_vex_results("test_fs_multi.json", expected)
    return False

def main():
    parser = argparse.ArgumentParser(description="Test filesystem vulnerability analysis")
    parser.add_argument("--test", choices=["smb", "nfs", "mixed", "all"], default="all",
                       help="Which test to run")
    
    args = parser.parse_args()
    
    # Change to tests directory
    os.chdir(Path(__file__).parent)
    
    print("🧪 FILESYSTEM VULNERABILITY ANALYSIS TEST SUITE")
    print("=" * 60)
    print("Testing SMB/CIFS, NFS, EXT4, and BTRFS pattern detection")
    print("=" * 60)
    
    tests = []
    results = []
    
    if args.test in ["smb", "all"]:
        tests.extend([
            ("SMB with CIFS", test_smb_with_cifs),
            ("SMB without CIFS", test_smb_without_cifs)
        ])
    
    if args.test in ["nfs", "all"]:
        tests.append(("NFS without support", test_nfs_without_support))
    
    if args.test in ["mixed", "all"]:
        tests.append(("Mixed filesystems", test_mixed_filesystems))
    
    # Run all tests
    for test_name, test_func in tests:
        print(f"\n🚀 Starting test: {test_name}")
        success = test_func()
        results.append((test_name, success))
        
        if success:
            print(f"✅ {test_name}: PASSED")
        else:
            print(f"❌ {test_name}: FAILED")
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_name:.<40} {status}")
    
    print(f"\nResults: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All filesystem tests passed!")
        return 0
    else:
        print("⚠️  Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
