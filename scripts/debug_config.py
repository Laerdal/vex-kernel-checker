#!/usr/bin/env python3
"""
Quick debug script to check what's happening with config parsing.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import importlib.util
spec = importlib.util.spec_from_file_location("vex_kernel_checker_fresh", 
                                              "../vex-kernel-checker.py")
vex_fresh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vex_fresh)
VexKernelChecker = vex_fresh.VexKernelChecker

# Test the load_kernel_config function first
print("=== Testing load_kernel_config ===")
kernel_config = VexKernelChecker.load_kernel_config("test_demo.config")
print(f"Loaded config options: {kernel_config}")

# Test raw config lines
print("\n=== Testing extract_arch_from_config with raw config lines ===")
test_config_lines = ['CONFIG_X86_64=y', 'CONFIG_64BIT=y', 'CONFIG_NET=y']
print(f"Input: {test_config_lines}")
arch, arch_config = VexKernelChecker.extract_arch_from_config(test_config_lines)
print(f"Result: {arch}, {arch_config}")

# Test parsed config lines
print("\n=== Testing extract_arch_from_config with parsed config ===")
test_config_parsed = ['CONFIG_X86_64', 'CONFIG_64BIT', 'CONFIG_NET']
print(f"Input: {test_config_parsed}")
arch2, arch_config2 = VexKernelChecker.extract_arch_from_config(test_config_parsed)
print(f"Result: {arch2}, {arch_config2}")
