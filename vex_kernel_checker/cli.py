#!/usr/bin/env python3
"""
Command-line interface entry point for VEX Kernel Checker.

This module provides the main() function for the console_scripts entry point.
"""

import sys
import os

# Add parent directory to path to import from vex-kernel-checker.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    """Main entry point for the CLI."""
    # Import here to avoid circular imports
    import importlib.util

    # Load the main script as a module
    script_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "vex-kernel-checker.py",
    )

    spec = importlib.util.spec_from_file_location("vex_kernel_checker_main", script_path)
    if spec is None or spec.loader is None:
        print(f"Error: Could not load {script_path}", file=sys.stderr)
        return 1

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module.main()


if __name__ == "__main__":
    sys.exit(main())
