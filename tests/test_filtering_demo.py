#!/usr/bin/env python3
"""
Test script to demonstrate the improved configuration filtering.
This shows the difference between the old (verbose) and new (filtered) output.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our VEX Kernel Checker
exec(open('vex-kernel-checker.py').read())

def test_config_filtering():
    """Test the configuration filtering functionality."""
    print("=== Testing Configuration Option Filtering ===\n")
    
    # Create a checker instance
    checker = VexKernelChecker()
    
    # Simulate config options that might be found during analysis
    # (mix of relevant and irrelevant options)
    found_config_options = {
        # Relevant functional options
        'CONFIG_NET',
        'CONFIG_USB', 
        'CONFIG_DRM_TTM_HELPER',
        'CONFIG_MACSEC',
        'CONFIG_HID_MAYFLASH',
        'CONFIG_AF_RXRPC',
        
        # Irrelevant build/debug options (should be filtered out)
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
    
    # Test the filtering function
    relevant_options = checker._filter_relevant_config_options(found_config_options)
    
    print(f"Original config options found ({len(found_config_options)} total):")
    for option in sorted(found_config_options):
        print(f"  {option}")
    
    print(f"\nFiltered relevant options ({len(relevant_options)} total):")
    for option in sorted(relevant_options):
        print(f"  {option}")
    
    print(f"\nFiltered out ({len(found_config_options) - len(relevant_options)} options):")
    filtered_out = found_config_options - relevant_options
    for option in sorted(filtered_out):
        print(f"  {option}")
    
    # Simulate the kernel config (missing some relevant options)
    kernel_config = [
        'CONFIG_NET',
        'CONFIG_USB',
        # CONFIG_DRM_TTM_HELPER missing
        # CONFIG_MACSEC missing
        # etc.
    ]
    
    print(f"\nKernel config has:")
    for option in sorted(kernel_config):
        print(f"  {option}")
    
    # Test the analysis with old vs new approach
    print(f"\n=== Analysis Results ===")
    
    # Old approach (would show all missing options)
    all_missing = found_config_options - set(kernel_config)
    print(f"\nOLD approach - Missing options ({len(all_missing)} total):")
    print(f"\"Required configuration options not enabled: {', '.join(sorted(all_missing))}\"")
    
    # New approach (shows only relevant missing options)
    relevant_missing = relevant_options - set(kernel_config)
    print(f"\nNEW approach - Missing relevant options ({len(relevant_missing)} total):")
    print(f"\"Required configuration options not enabled: {', '.join(sorted(relevant_missing))}\"")
    
    print(f"\nImprovement: Reduced from {len(all_missing)} to {len(relevant_missing)} options in output!")
    print(f"Reduction: {(len(all_missing) - len(relevant_missing)) / len(all_missing) * 100:.1f}%")

if __name__ == "__main__":
    test_config_filtering()
