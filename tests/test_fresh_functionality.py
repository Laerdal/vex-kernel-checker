#!/usr/bin/env python3
"""
Simple test script to verify VEX Kernel Checker functionality
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, '/home/kopdal/dev/laerdal/simpad-plus-top-release/vex-kernel-checker')

try:
    # Import the script
    print("Importing VEX Kernel Checker...")
    exec(open('../vex-kernel-checker.py').read())
    
    print("✅ Import successful!")
    
    # Test basic initialization
    print("Testing VexKernelChecker initialization...")
    checker = VexKernelChecker(verbose=True)
    print("✅ VexKernelChecker initialized successfully!")
    
    # Test some basic properties
    print(f"API rate limit delay: {checker.API_RATE_LIMIT_DELAY}")
    print(f"Max parallel workers: {checker.MAX_PARALLEL_WORKERS}")
    print(f"Check patches enabled: {checker.check_patches}")
    
    # Test cache operations
    print("Testing cache operations...")
    checker.clear_all_caches()
    print("✅ Cache clearing works!")
    
    # Test configuration patterns
    print("Testing pattern compilation...")
    patterns = checker._compile_config_patterns()
    print(f"✅ Compiled {len(patterns)} config patterns")
    
    print("\n🎉 All basic tests passed! The fresh VEX Kernel Checker is working.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
