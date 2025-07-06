#!/usr/bin/env python3

import sys
import os
import re
from typing import Optional, Tuple

def extract_arch_info(path: str) -> Tuple[Optional[str], Optional[str]]:
    """Extract architecture information from file path."""
    arch_patterns = {
        'x86': r'arch/x86/',
        'arm64': r'arch/arm64/',
        'arm': r'arch/arm/',
        'mips': r'arch/mips/',
        'powerpc': r'arch/powerpc/',
        'riscv': r'arch/riscv/',
        's390': r'arch/s390/',
        'sparc': r'arch/sparc/',
    }
    
    for arch, pattern in arch_patterns.items():
        if re.search(pattern, path):
            # Special mapping for architectures
            if arch == 'arm':
                return arch, "CONFIG_ARM"
            elif arch == 'arm64':
                return arch, "CONFIG_ARM64"
            else:
                return arch, f"CONFIG_{arch.upper()}"
    
    return None, None

def test_arch_extraction():
    """Test architecture extraction."""
    test_cases = [
        ("arch/arm/mach-omap2/board-generic.c", "arm", "CONFIG_ARM"),
        ("arch/arm64/kernel/setup.c", "arm64", "CONFIG_ARM64"), 
        ("arch/x86/kernel/setup.c", "x86", "CONFIG_X86"),
        ("drivers/net/ethernet/intel/e1000/e1000_main.c", None, None),
    ]
    
    print("Testing architecture extraction...")
    
    for path, expected_arch, expected_config in test_cases:
        arch, config = extract_arch_info(path)
        print(f"Path: {path}")
        print(f"  Expected: arch={expected_arch}, config={expected_config}")
        print(f"  Got:      arch={arch}, config={config}")
        
        if arch == expected_arch and config == expected_config:
            print(f"  ✅ PASS")
        else:
            print(f"  ❌ FAIL")
            return False
        print()
    
    print("All architecture extraction tests passed!")
    return True

if __name__ == "__main__":
    success = test_arch_extraction()
    sys.exit(0 if success else 1)
