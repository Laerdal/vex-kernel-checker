#!/usr/bin/env python3

import re

def test_arch_regex():
    path = 'arch/arm/mach-omap2/board-generic.c'
    pattern = r'arch/arm/'
    result = re.search(pattern, path)
    print(f'Pattern: {pattern}')
    print(f'Path: {path}')
    print(f'Match: {result}')
    if result:
        print('Found match!')
        return True
    else:
        print('No match')
        return False

if __name__ == "__main__":
    test_arch_regex()
