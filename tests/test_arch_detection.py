#!/usr/bin/env python3
"""
Test script for the updated architecture detection functionality.
Tests both config-based and path-based architecture detection.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the fresh implementation
    import importlib.util
    spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", 
                                                  "../vex-kernel-checker.py")
    vex_fresh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vex_fresh)
    VexKernelChecker = vex_fresh.VexKernelChecker
    print("✅ Successfully imported VexKernelChecker from fresh implementation")
except ImportError as e:
    print(f"❌ Failed to import: {e}")
    sys.exit(1)

def test_config_based_arch_detection():
    """Test the new config-based architecture detection."""
    print("\n=== Testing Config-Based Architecture Detection ===")
    
    # Test various architecture configurations
    test_configs = [
        # ARM64
        (['CONFIG_ARM64', 'CONFIG_ARM64_4K_PAGES', 'CONFIG_NET'], 'arm64', 'CONFIG_ARM64'),
        
        # ARM (32-bit)
        (['CONFIG_ARM', 'CONFIG_ARM_THUMB', 'CONFIG_NET'], 'arm', 'CONFIG_ARM'),
        
        # x86_64
        (['CONFIG_X86_64', 'CONFIG_64BIT', 'CONFIG_NET'], 'x86_64', 'CONFIG_X86_64'),
        
        # x86 (32-bit)
        (['CONFIG_X86', 'CONFIG_X86_32', 'CONFIG_NET'], 'x86', 'CONFIG_X86'),
        
        # MIPS
        (['CONFIG_MIPS', 'CONFIG_MIPS32_R1', 'CONFIG_NET'], 'mips', 'CONFIG_MIPS'),
        
        # PowerPC
        (['CONFIG_POWERPC', 'CONFIG_PPC64', 'CONFIG_NET'], 'powerpc', 'CONFIG_POWERPC'),
        
        # RISCV
        (['CONFIG_RISCV', 'CONFIG_64BIT', 'CONFIG_NET'], 'riscv', 'CONFIG_RISCV'),
        
        # No architecture detected
        (['CONFIG_NET', 'CONFIG_USB', 'CONFIG_PCI'], None, None)
    ]
    
    success_count = 0
    total_tests = len(test_configs)
    
    for i, (config_lines, expected_arch, expected_config) in enumerate(test_configs, 1):
        print(f"\nTest {i}: {config_lines}")
        
        detected_arch, detected_config = VexKernelChecker.extract_arch_from_config(config_lines)
        
        if detected_arch == expected_arch and detected_config == expected_config:
            print(f"  ✅ PASS: Detected {detected_arch} ({detected_config})")
            success_count += 1
        else:
            print(f"  ❌ FAIL: Expected {expected_arch} ({expected_config}), got {detected_arch} ({detected_config})")
    
    print(f"\nConfig-based detection: {success_count}/{total_tests} tests passed")
    return success_count == total_tests

def test_arch_specific_configs():
    """Test getting architecture-specific configuration options."""
    print("\n=== Testing Architecture-Specific Config Generation ===")
    
    test_cases = [
        ('arm', 'CONFIG_ARM'),
        ('arm64', 'CONFIG_ARM64'),
        ('x86_64', 'CONFIG_X86_64'),
        ('mips', 'CONFIG_MIPS'),
        ('powerpc', 'CONFIG_POWERPC'),
        (None, None)
    ]
    
    all_passed = True
    for arch, arch_config in test_cases:
        print(f"\nTesting architecture: {arch}")
        
        checker = VexKernelChecker(arch=arch, arch_config=arch_config)
        arch_configs = checker.get_arch_specific_configs()
        
        if arch:
            if arch_config in arch_configs:
                print(f"  ✅ PASS: Found expected config {arch_config} in {arch_configs}")
            else:
                print(f"  ❌ FAIL: Expected config {arch_config} not found in {arch_configs}")
                all_passed = False
        else:
            if not arch_configs:
                print(f"  ✅ PASS: No architecture configs (as expected)")
            else:
                print(f"  ❌ FAIL: Unexpected configs found: {arch_configs}")
                all_passed = False
    
    return all_passed

def test_path_based_arch_detection():
    """Test the legacy path-based architecture detection."""
    print("\n=== Testing Path-Based Architecture Detection (Legacy) ===")
    
    test_paths = [
        ('arch/arm64/kernel/setup.c', 'arm64', 'CONFIG_ARM64'),
        ('arch/arm/mach-imx/cpu.c', 'arm', 'CONFIG_ARM'),
        ('arch/x86/kernel/setup.c', 'x86', 'CONFIG_X86'),
        ('arch/mips/kernel/setup.c', 'mips', 'CONFIG_MIPS'),
        ('arch/powerpc/kernel/setup.c', 'powerpc', 'CONFIG_POWERPC'),
        ('drivers/net/ethernet/intel/e1000e/netdev.c', None, None),
        ('fs/ext4/inode.c', None, None)
    ]
    
    success_count = 0
    total_tests = len(test_paths)
    
    for path, expected_arch, expected_config in test_paths:
        detected_arch, detected_config = VexKernelChecker.extract_arch_info(path)
        
        if detected_arch == expected_arch and detected_config == expected_config:
            print(f"  ✅ PASS: {path} -> {detected_arch} ({detected_config})")
            success_count += 1
        else:
            print(f"  ❌ FAIL: {path} -> Expected {expected_arch} ({expected_config}), got {detected_arch} ({detected_config})")
    
    print(f"\nPath-based detection: {success_count}/{total_tests} tests passed")
    return success_count == total_tests

def test_integration_with_demo_config():
    """Test with the actual demo configuration file."""
    print("\n=== Testing Integration with Demo Config ===")
    
    demo_config_path = "test_demo.config"
    if not os.path.exists(demo_config_path):
        print(f"❌ Demo config file not found: {demo_config_path}")
        return False
    
    try:
        # Load the demo config
        kernel_config = VexKernelChecker.load_kernel_config(demo_config_path)
        print(f"Loaded {len(kernel_config)} config options from demo file")
        
        # Extract architecture
        arch, arch_config = VexKernelChecker.extract_arch_from_config(kernel_config)
        print(f"Detected architecture: {arch} ({arch_config})")
        
        # Initialize checker with detected architecture
        checker = VexKernelChecker(verbose=True, arch=arch, arch_config=arch_config)
        
        # Test getting architecture-specific configs
        arch_configs = checker.get_arch_specific_configs()
        print(f"Architecture-specific configs: {arch_configs}")
        
        # Test in_kernel_config with some sample config options
        sample_configs = {'CONFIG_NET', 'CONFIG_USB'}
        analysis = checker.in_kernel_config(sample_configs, kernel_config)
        print(f"Sample analysis: {analysis.state} - {analysis.detail}")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def main():
    """Run all architecture detection tests."""
    print("Testing Updated Architecture Detection Functionality")
    print("=" * 60)
    
    all_passed = True
    
    # Run all tests
    tests = [
        test_config_based_arch_detection,
        test_arch_specific_configs,
        test_path_based_arch_detection,
        test_integration_with_demo_config
    ]
    
    for test_func in tests:
        try:
            result = test_func()
            if not result:
                all_passed = False
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed with exception: {e}")
            all_passed = False
    
    # Summary
    print("\n" + "=" * 60)
    if all_passed:
        print("🎉 All architecture detection tests passed!")
        print("✅ Config-based architecture detection is working correctly")
        print("✅ Architecture-specific configuration generation is working")
        print("✅ Legacy path-based detection still works")
        print("✅ Integration with kernel configuration files is working")
    else:
        print("❌ Some tests failed. Please review the output above.")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
