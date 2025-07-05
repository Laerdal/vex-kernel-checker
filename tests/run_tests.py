#!/usr/bin/env python3
"""
Test runner for VEX Kernel Checker.

This script provides an easy way to run all tests for the VEX Kernel Checker
with proper environment setup and reporting.
"""

import os
import sys
import subprocess
import argparse
import time
from pathlib import Path

def run_tests(test_pattern=None, verbose=False, coverage=False):
    """Run the test suite.
    
    Args:
        test_pattern: Pattern to match specific tests (e.g., 'test_initialization')
        verbose: Enable verbose test output
        coverage: Run tests with coverage reporting
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    tests_dir = project_root / "tests"
    
    # Change to project root for proper imports
    os.chdir(project_root)
    
    # Build the test command
    if coverage:
        # Install coverage if not available
        try:
            import coverage
        except ImportError:
            print("Installing coverage package...")
            subprocess.run([sys.executable, "-m", "pip", "install", "coverage"], check=True)
        
        cmd = [sys.executable, "-m", "coverage", "run", "--source=.", "-m", "unittest"]
    else:
        cmd = [sys.executable, "-m", "unittest"]
    
    # Add test discovery
    if test_pattern:
        cmd.extend(["discover", "-s", str(tests_dir), "-p", f"*{test_pattern}*"])
    else:
        cmd.extend(["discover", "-s", str(tests_dir), "-p", "test_*.py"])
    
    # Add verbosity
    if verbose:
        cmd.append("-v")
    
    print(f"Running tests from: {tests_dir}")
    print(f"Command: {' '.join(cmd)}")
    print("-" * 60)
    
    start_time = time.time()
    
    try:
        # Run the tests
        result = subprocess.run(cmd, cwd=project_root)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("-" * 60)
        print(f"Tests completed in {duration:.2f} seconds")
        
        if coverage and result.returncode == 0:
            print("\nGenerating coverage report...")
            subprocess.run([sys.executable, "-m", "coverage", "report", "-m"], cwd=project_root)
            
            # Generate HTML coverage report
            html_dir = project_root / "htmlcov"
            subprocess.run([sys.executable, "-m", "coverage", "html"], cwd=project_root)
            print(f"HTML coverage report generated in: {html_dir}")
        
        return result.returncode
        
    except KeyboardInterrupt:
        print("\nTests interrupted by user")
        return 1
    except Exception as e:
        print(f"Error running tests: {e}")
        return 1

def check_dependencies():
    """Check if all required dependencies are available."""
    missing_deps = []
    
    # Check for required packages
    required_packages = [
        'selenium',
        'requests'
    ]
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_deps.append(package)
    
    if missing_deps:
        print("Missing required dependencies:")
        for dep in missing_deps:
            print(f"  - {dep}")
        print(f"\nInstall with: pip install {' '.join(missing_deps)}")
        return False
    
    return True

def run_quick_test():
    """Run a quick smoke test to verify basic functionality."""
    print("Running quick smoke test...")
    
    # Import the main module to check for syntax errors
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        
        # Try to import and instantiate the checker
        import importlib.util
        spec = importlib.util.spec_from_file_location("vex_kernel_checker", 
                                                     Path(__file__).parent.parent / "vex-kernel-checker.py")
        vkc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vkc_module)
        
        # Test basic instantiation
        checker = vkc_module.VexKernelChecker(verbose=False)
        print("✓ Module imports successfully")
        print("✓ VexKernelChecker instantiates correctly")
        
        # Test basic methods
        test_path = "/fake/path/drivers/net/test.c"
        arch, config = vkc_module.VexKernelChecker.extract_arch_info(test_path)
        print("✓ Basic methods work correctly")
        
        print("✓ Quick smoke test passed")
        return True
        
    except Exception as e:
        print(f"✗ Quick smoke test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Run VEX Kernel Checker tests")
    parser.add_argument('--pattern', '-p', help='Test pattern to match')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose test output')
    parser.add_argument('--coverage', '-c', action='store_true', help='Run with coverage reporting')
    parser.add_argument('--quick', '-q', action='store_true', help='Run quick smoke test only')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies only')
    
    args = parser.parse_args()
    
    if args.check_deps:
        if check_dependencies():
            print("✓ All dependencies are available")
            return 0
        else:
            return 1
    
    if args.quick:
        if run_quick_test():
            return 0
        else:
            return 1
    
    # Check dependencies before running full tests
    if not check_dependencies():
        print("Please install missing dependencies before running tests")
        return 1
    
    # Run the test suite
    return run_tests(
        test_pattern=args.pattern,
        verbose=args.verbose,
        coverage=args.coverage
    )

if __name__ == '__main__':
    sys.exit(main())
