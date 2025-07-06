#!/usr/bin/env python3
"""
Simple validation script for architecture detection functionality.
"""

import sys
import os

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import the module
import importlib.util
spec = importlib.util.spec_from_file_location("vex_main", "../vex-kernel-checker.py")
vex_fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_fresh)
VexKernelChecker = vex_fresh.VexKernelChecker

def main():
    print("=== Validating Architecture Detection ===")
    
    # Test 1: Legacy path-based detection
    print("\n1. Testing legacy path-based detection:")
    test_paths = [
        "arch/arm/mach-omap2/board-generic.c",
        "arch/x86/kernel/setup.c",
        "arch/arm64/kernel/setup.c",
        "net/core/skbuff.c"
    ]
    
    for path in test_paths:
        arch, config = VexKernelChecker.extract_arch_info(path)
        print(f"  {path} -> {arch}, {config}")
    
    # Test 2: Config-based detection
    print("\n2. Testing config-based detection:")
    test_configs = [
        ["CONFIG_ARM", "CONFIG_NET"],
        ["CONFIG_ARM64", "CONFIG_USB"],
        ["CONFIG_X86_64", "CONFIG_PCI"],
        ["CONFIG_NET", "CONFIG_USB"]
    ]
    
    for configs in test_configs:
        arch, config = VexKernelChecker.extract_arch_from_config(configs)
        print(f"  {configs} -> {arch}, {config}")
    
    # Test 3: Integration test
    print("\n3. Testing with demo config file:")
    if os.path.exists("test_demo.config"):
        kernel_config = VexKernelChecker.load_kernel_config("test_demo.config")
        arch, config = VexKernelChecker.extract_arch_from_config(kernel_config)
        print(f"  Demo config detected: {arch}, {config}")
    else:
        print("  Demo config file not found")
    
    print("\n✅ Architecture detection validation complete!")

if __name__ == "__main__":
    main()
