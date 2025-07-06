#!/usr/bin/env python3
"""
Quick test for the VEX Kernel Checker Fresh implementation.
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from the fresh implementation
import importlib.util
spec = importlib.util.spec_from_file_location("vex_kernel_checker", "../vex-kernel-checker.py")
vex_fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_fresh)

def test_architecture_extraction():
    """Test architecture information extraction from file paths."""
    print("Testing architecture extraction...")
    
    # Test ARM architecture
    arm_path = "arch/arm/mach-omap2/board-generic.c"
    arch, config = vex_fresh.VexKernelChecker.extract_arch_info(arm_path)
    print(f"ARM path: {arm_path} -> arch={arch}, config={config}")
    assert arch == "arm", f"Expected 'arm', got '{arch}'"
    assert config == "CONFIG_ARM", f"Expected 'CONFIG_ARM', got '{config}'"
    
    # Test ARM64 architecture
    arm64_path = "arch/arm64/kernel/setup.c"
    arch, config = vex_fresh.VexKernelChecker.extract_arch_info(arm64_path)
    print(f"ARM64 path: {arm64_path} -> arch={arch}, config={config}")
    assert arch == "arm64", f"Expected 'arm64', got '{arch}'"
    assert config == "CONFIG_ARM64", f"Expected 'CONFIG_ARM64', got '{config}'"
    
    # Test x86 architecture
    x86_path = "arch/x86/kernel/setup.c"
    arch, config = vex_fresh.VexKernelChecker.extract_arch_info(x86_path)
    print(f"x86 path: {x86_path} -> arch={arch}, config={config}")
    assert arch == "x86", f"Expected 'x86', got '{arch}'"
    assert config == "CONFIG_X86", f"Expected 'CONFIG_X86', got '{config}'"
    
    # Test non-architecture path
    non_arch_path = "drivers/net/ethernet/intel/e1000/e1000_main.c"
    arch, config = vex_fresh.VexKernelChecker.extract_arch_info(non_arch_path)
    print(f"Non-arch path: {non_arch_path} -> arch={arch}, config={config}")
    assert arch is None, f"Expected None, got '{arch}'"
    assert config is None, f"Expected None, got '{config}'"
    
    print("✅ Architecture extraction tests passed!")

def test_config_filtering():
    """Test configuration option filtering functionality."""
    print("Testing configuration filtering...")
    
    checker = vex_fresh.VexKernelChecker(verbose=False)
    
    test_options = {
        # These should be kept (functional options)
        'CONFIG_NET',
        'CONFIG_USB',
        'CONFIG_DRM_TTM_HELPER',
        'CONFIG_MACSEC',
        'CONFIG_HID_MAYFLASH',

        # These should be filtered out (build/debug options)
        'CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN',
        'CONFIG_GCC_PLUGIN_RANDSTRUCT',
        'CONFIG_LTO_CLANG',
        'CONFIG_CFI_CLANG',
        'CONFIG_DEBUG_INFO_BTF',
        'CONFIG_FTRACE_MCOUNT_USE_RECORDMCOUNT',
        'CONFIG_FRAME_WARN',
        'CONFIG_STRIP_ASM_SYMS',
        'CONFIG_HEADERS_INSTALL',
        'CONFIG_EXPERT',
        'CONFIG_SUPERH',
        'CONFIG_UML',
        'CONFIG_HAVE_STACK_VALIDATION'
    }

    filtered = checker._filter_relevant_config_options(test_options)
    print(f"Original options: {len(test_options)}")
    print(f"Filtered options: {len(filtered)}")
    print(f"Filtered configs: {sorted(filtered)}")
    
    # Expected to keep the functional options
    expected_kept = {'CONFIG_NET', 'CONFIG_USB', 'CONFIG_DRM_TTM_HELPER', 'CONFIG_MACSEC', 'CONFIG_HID_MAYFLASH'}
    assert expected_kept.issubset(filtered), f"Expected to keep {expected_kept}, but filtered result is {filtered}"
    
    # Expected to filter out build/debug options
    should_be_filtered = {'CONFIG_CC_HAS_AUTO_VAR_INIT_PATTERN', 'CONFIG_GCC_PLUGIN_RANDSTRUCT', 'CONFIG_LTO_CLANG', 'CONFIG_DEBUG_INFO_BTF', 'CONFIG_EXPERT'}
    assert not should_be_filtered.intersection(filtered), f"Expected to filter out {should_be_filtered}, but some were kept in {filtered}"
    
    print("✅ Configuration filtering tests passed!")

def test_basic_functionality():
    """Test basic functionality of the VEX Kernel Checker."""
    print("Testing basic functionality...")
    
    # Test initialization
    checker = vex_fresh.VexKernelChecker(verbose=False)
    print(f"✅ Checker initialized successfully")
    
    # Test with web driver disabled
    checker_no_web = vex_fresh.VexKernelChecker(verbose=False, disable_patch_checking=True)
    print(f"✅ Checker with no web driver initialized successfully")
    
    print("✅ Basic functionality tests passed!")

if __name__ == "__main__":
    print("=== VEX Kernel Checker Fresh - Quick Tests ===")
    
    try:
        test_basic_functionality()
        test_architecture_extraction()
        test_config_filtering()
        
        print("\n🎉 All tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
