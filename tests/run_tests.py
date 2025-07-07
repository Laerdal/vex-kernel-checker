#!/usr/bin/env python3
"""
Comprehensive test runner for VEX Kernel Checker.

This script runs all unit tests and provides test coverage information.
"""

import os
import sys
import unittest
import argparse
import time
from pathlib import Path

# Add the parent directory to the path to import the vex_kernel_checker module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def discover_and_run_tests(
    test_directory: str = None,
    pattern: str = "test_*.py",
    verbosity: int = 2,
    failfast: bool = False,
) -> unittest.TestResult:
    """
    Discover and run all tests in the specified directory.

    Args:
        test_directory: Directory containing test files
        pattern: Test file pattern
        verbosity: Test output verbosity level
        failfast: Stop on first failure

    Returns:
        TestResult object
    """
    if test_directory is None:
        test_directory = os.path.dirname(os.path.abspath(__file__))

    # Discover tests
    loader = unittest.TestLoader()
    start_dir = test_directory
    suite = loader.discover(start_dir, pattern=pattern)

    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=verbosity, failfast=failfast, buffer=True
    )  # Capture stdout/stderr

    print(f"Discovering tests in: {start_dir}")
    print(f"Test pattern: {pattern}")
    print(f"Verbosity level: {verbosity}")
    print("=" * 70)

    start_time = time.time()
    result = runner.run(suite)
    end_time = time.time()

    print("=" * 70)
    print(f"Tests completed in {end_time - start_time:.2f} seconds")

    return result


def run_specific_test_file(test_file: str, verbosity: int = 2) -> unittest.TestResult:
    """
    Run a specific test file.

    Args:
        test_file: Path to test file
        verbosity: Test output verbosity level

    Returns:
        TestResult object
    """
    # Import the test module
    test_dir = os.path.dirname(test_file)
    test_module = os.path.basename(test_file).replace(".py", "")

    sys.path.insert(0, test_dir)

    try:
        module = __import__(test_module)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)

        runner = unittest.TextTestRunner(verbosity=verbosity, buffer=True)
        return runner.run(suite)
    except ImportError as e:
        print(f"Error importing test module {test_module}: {e}")
        return None


def run_coverage_analysis():
    """Run tests with coverage analysis if coverage.py is available."""
    try:
        import coverage

        # Initialize coverage
        cov = coverage.Coverage()
        cov.start()

        # Run tests
        result = discover_and_run_tests(verbosity=1)

        # Stop coverage and generate report
        cov.stop()
        cov.save()

        print("\n" + "=" * 70)
        print("COVERAGE REPORT")
        print("=" * 70)

        # Print coverage report
        cov.report(show_missing=True)

        # Generate HTML report if requested
        print("\nGenerating HTML coverage report...")
        cov.html_report(directory="htmlcov")
        print("HTML coverage report generated in 'htmlcov' directory")

        return result

    except ImportError:
        print("Coverage.py not available. Install with: pip install coverage")
        return discover_and_run_tests()


def validate_environment():
    """Validate that the test environment is properly set up."""
    print("Validating test environment...")

    # Check if vex_kernel_checker module can be imported
    try:
        import vex_kernel_checker

        print("✅ vex_kernel_checker module can be imported")
    except ImportError as e:
        print(f"❌ Cannot import vex_kernel_checker: {e}")
        return False

    # Check if individual components can be imported
    components = [
        "vex_kernel_checker.common",
        "vex_kernel_checker.base",
        "vex_kernel_checker.cve_manager",
        "vex_kernel_checker.config_analyzer",
        "vex_kernel_checker.vulnerability_analyzer",
        "vex_kernel_checker.patch_manager",
        "vex_kernel_checker.architecture_manager",
        "vex_kernel_checker.report_generator",
        "vex_kernel_checker.main_checker",
    ]

    failed_imports = []
    for component in components:
        try:
            __import__(component)
            print(f"✅ {component}")
        except ImportError as e:
            print(f"❌ {component}: {e}")
            failed_imports.append(component)

    if failed_imports:
        print(f"\n❌ Failed to import {len(failed_imports)} components")
        return False

    print("✅ All components imported successfully")
    return True


def run_quick_smoke_tests():
    """Run a quick smoke test to verify basic functionality."""
    print("Running quick smoke tests...")

    try:
        # Test basic imports and initialization
        from vex_kernel_checker.common import VulnerabilityState, CVEInfo
        from vex_kernel_checker.base import VexKernelCheckerBase
        from vex_kernel_checker.cve_manager import CVEDataManager
        from vex_kernel_checker.config_analyzer import ConfigurationAnalyzer

        # Test basic object creation
        base = VexKernelCheckerBase()
        cve_manager = CVEDataManager(verbose=False)
        config_analyzer = ConfigurationAnalyzer(verbose=False)

        # Test enum values
        assert VulnerabilityState.EXPLOITABLE.value == "exploitable"
        assert VulnerabilityState.NOT_AFFECTED.value == "not_affected"

        # Test CVEInfo creation
        cve_info = CVEInfo(cve_id="CVE-TEST-12345", description="Test CVE")
        assert cve_info.cve_id == "CVE-TEST-12345"

        print("✅ Smoke tests passed")
        return True

    except Exception as e:
        print(f"❌ Smoke test failed: {e}")
        return False


def main():
    """Main test runner function."""
    parser = argparse.ArgumentParser(description="VEX Kernel Checker Test Runner")
    parser.add_argument(
        "--coverage", action="store_true", help="Run tests with coverage analysis"
    )
    parser.add_argument(
        "--smoke", action="store_true", help="Run quick smoke tests only"
    )
    parser.add_argument(
        "--validate", action="store_true", help="Validate environment only"
    )
    parser.add_argument(
        "--pattern", default="test_*.py", help="Test file pattern (default: test_*.py)"
    )
    parser.add_argument(
        "--verbosity",
        type=int,
        default=2,
        help="Test output verbosity (0-2, default: 2)",
    )
    parser.add_argument(
        "--failfast", action="store_true", help="Stop on first test failure"
    )
    parser.add_argument("--file", help="Run specific test file")

    args = parser.parse_args()

    print("VEX Kernel Checker Test Runner")
    print("=" * 70)

    # Validate environment first
    if not validate_environment():
        print("\n❌ Environment validation failed")
        sys.exit(1)

    if args.validate:
        print("\n✅ Environment validation completed successfully")
        return

    if args.smoke:
        success = run_quick_smoke_tests()
        sys.exit(0 if success else 1)

    if args.file:
        if not os.path.exists(args.file):
            print(f"❌ Test file not found: {args.file}")
            sys.exit(1)
        result = run_specific_test_file(args.file, args.verbosity)
    elif args.coverage:
        result = run_coverage_analysis()
    else:
        result = discover_and_run_tests(
            pattern=args.pattern, verbosity=args.verbosity, failfast=args.failfast
        )

    if result:
        # Print summary
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Skipped: {len(result.skipped)}")

        if result.failures:
            print(f"\n❌ {len(result.failures)} test(s) failed")
        if result.errors:
            print(f"❌ {len(result.errors)} test(s) had errors")

        success = len(result.failures) == 0 and len(result.errors) == 0

        if success:
            print("✅ All tests passed!")
        else:
            print("❌ Some tests failed")

        sys.exit(0 if success else 1)
    else:
        print("❌ Test execution failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
