#!/usr/bin/env python3
"""
VEX Kernel Checker - Main CLI Application.

This script provides the main command-line interface for the VEX Kernel Checker
using the refactored modular components.

MIT License - See LICENSE file for details.
"""

import argparse
import os
import sys
import time
import traceback
from typing import Dict, List, Optional

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vex_kernel_checker import (  # noqa: E402
    PerformanceTracker,
    VexKernelChecker,
    VexKernelCheckerBase,
)


def validate_input_files(args) -> bool:
    """Validate that all required input files exist."""
    if not os.path.exists(args.vex_file):
        print(f'Error: VEX file not found: {args.vex_file}')
        return False

    if not os.path.exists(args.kernel_config):
        print(f'Error: Kernel config file not found: {args.kernel_config}')
        return False

    if not os.path.exists(args.kernel_source):
        print(f'Error: Kernel source directory not found: {args.kernel_source}')
        return False

    return True


def print_analysis_overview(
    vex_data: Dict,
    kernel_config: List[str],
    arch: Optional[str],
    disable_patch_checking: bool,
    api_key: Optional[str],
) -> None:
    """Print analysis overview before starting."""
    total_vulns = len(vex_data.get('vulnerabilities', []))
    print('📋 Analysis Overview:')
    print(f'   Total vulnerabilities: {total_vulns}')
    print(f'   Kernel configuration: {len(kernel_config)} options')
    print(f'   Architecture: {arch if arch else "Unknown"}')
    print(f'   Patch checking: {"Enabled" if not disable_patch_checking else "Disabled"}')
    print(f'   API key: {"Provided" if api_key else "Not provided (rate limited)"}')
    print()


def print_final_summary(report: Dict) -> None:
    """Print final analysis summary."""
    exploitable_count = report.get('exploitable', 0)
    not_affected_count = report.get('not_affected', 0)
    in_triage_count = report.get('in_triage', 0)
    resolved_count = report.get('resolved', 0)
    resolved_with_pedigree_count = report.get('resolved_with_pedigree', 0)
    false_positive_count = report.get('false_positive', 0)

    print('\n🎯 Final Summary:')
    print(f'   ✅ Not affected: {not_affected_count}')
    print(f'   🔧 Resolved: {resolved_count}')
    print(f'   🔧📋 Resolved with pedigree: {resolved_with_pedigree_count}')
    print(f'   ⚠️  Exploitable: {exploitable_count}')
    print(f'   ❌ False positive: {false_positive_count}')
    print(f'   🔍 In triage: {in_triage_count}')

    if exploitable_count > 0:
        print(f'\n⚠️  Warning: {exploitable_count} vulnerabilities may affect this kernel')
        print('   Review analysis details and consider patches or config changes')

    if in_triage_count > 0:
        print(f'\n🔍 Note: {in_triage_count} vulnerabilities need manual review')


def setup_argument_parser() -> argparse.ArgumentParser:
    """Set up and configure the command line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            'VEX Kernel Checker - Analyze CVE vulnerabilities against kernel configurations\n\n'
            'By default, only processes CVEs that do not have an existing analysis. '
            'Use --reanalyse to re-analyze CVEs that already have results.'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Required arguments
    parser.add_argument('--vex-file', required=True, help='Path to VEX JSON file')
    parser.add_argument('--kernel-config', required=True, help='Path to kernel config file (.config)')
    parser.add_argument('--kernel-source', required=True, help='Path to kernel source directory')

    # Optional arguments
    parser.add_argument('--output', help='Output file path (default: update VEX file in place)')
    parser.add_argument(
        '--reanalyse',
        action='store_true',
        help='Re-analyze all vulnerabilities, including those with existing analysis (default: only analyze CVEs without analysis)',
    )
    parser.add_argument('--cve-id', help='Process only specific CVE ID')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument(
        '--config-only',
        action='store_true',
        help='Disable patch checking and perform config-only analysis (faster but less accurate)',
    )
    parser.add_argument(
        '--api-key',
        help='NVD API key for CVE details (enables patch checking when combined with --edge-driver)',
    )
    parser.add_argument(
        '--edge-driver',
        help='Path to Edge WebDriver executable (enables patch checking when combined with --api-key)',
    )
    parser.add_argument('--clear-cache', action='store_true', help='Clear all internal caches before starting analysis')
    parser.add_argument('--performance-stats', action='store_true', help='Show detailed performance statistics')
    parser.add_argument(
        '--analyze-all-cves',
        action='store_true',
        help='Analyze all CVEs regardless of kernel relevance (default: only analyze kernel-related CVEs)',
    )
    parser.add_argument(
        '--detailed-timing',
        action='store_true',
        help='Show detailed method timing (verbose performance output)',
    )

    return parser


def load_and_validate_data(args, perf_tracker: PerformanceTracker):
    """Load VEX data and kernel configuration with validation."""
    # Load VEX data
    perf_tracker.start_timer('load_vex_data')
    print(f'Loading VEX data from {args.vex_file}...')
    vex_data = VexKernelCheckerBase.load_vex_file(args.vex_file)
    perf_tracker.end_timer('load_vex_data')

    # Load kernel config
    perf_tracker.start_timer('load_kernel_config')
    print(f'Loading kernel configuration from {args.kernel_config}...')
    kernel_config = VexKernelCheckerBase.load_kernel_config(args.kernel_config)
    perf_tracker.end_timer('load_kernel_config')

    print(f'Loaded {len(kernel_config)} configuration options')

    return vex_data, kernel_config


def setup_architecture_detection(kernel_config, perf_tracker: PerformanceTracker):
    """Extract and validate architecture from kernel configuration."""
    perf_tracker.start_timer('extract_architecture')
    arch, arch_config = VexKernelCheckerBase.extract_arch_from_config(kernel_config)
    perf_tracker.end_timer('extract_architecture')

    if arch and arch_config:
        print(f'Detected architecture: {arch} ({arch_config})')
    else:
        print('Warning: Could not detect architecture from kernel configuration')
        print('This may affect the accuracy of vulnerability analysis')
    
    return arch, arch_config


def setup_checker(args, arch):
    """Initialize the VEX Kernel Checker with provided arguments."""
    disable_patch_checking = args.config_only
    
    print('Initializing VEX Kernel Checker...')
    checker = VexKernelChecker(
        verbose=args.verbose,
        api_key=args.api_key,
        edge_driver_path=args.edge_driver,
        check_patches=not disable_patch_checking,
        analyze_all_cves=args.analyze_all_cves,
        arch=arch,  # Use the architecture detected from config
        detailed_timing=args.detailed_timing,
    )

    # Clear cache if requested
    if args.clear_cache:
        print('Clearing caches...')
        checker.clear_all_caches()
    
    return checker


def validate_and_show_vex_data(checker, vex_data):
    """Validate VEX data and show any issues."""
    validation_issues = checker.validate_vex_data(vex_data)
    if validation_issues:
        print('VEX data validation warnings:')
        for issue in validation_issues[:3]:
            print(f'  ⚠️  {issue}')
        if len(validation_issues) > 3:
            print(f'  ... and {len(validation_issues) - 3} more issues')
        print()


def perform_analysis(args, checker, vex_data, kernel_config, arch):
    """Execute the vulnerability analysis and return results."""
    print('\n' + '=' * 60)
    print('🚀 STARTING VULNERABILITY ANALYSIS')
    print('=' * 60)

    # Show analysis overview
    print_analysis_overview(
        vex_data, kernel_config, arch, args.config_only, args.api_key
    )

    start_time = time.time()

    updated_vex_data = checker.analyze_vulnerabilities(
        vex_data=vex_data,
        kernel_config=kernel_config,
        kernel_source_path=args.kernel_source,
        reanalyse=args.reanalyse,
        cve_id=args.cve_id,
    )

    analysis_time = time.time() - start_time
    print('\n' + '=' * 60)
    print('✅ ANALYSIS COMPLETED')
    print('=' * 60)
    print(f'⏱️  Total analysis time: {analysis_time:.2f} seconds')

    total_vulns = len(vex_data.get('vulnerabilities', []))
    if analysis_time > 0:
        print(f'📊 Performance: {total_vulns / analysis_time:.1f} CVEs/second')
    print()

    return updated_vex_data


def save_results_and_generate_reports(args, checker, updated_vex_data, output_file):
    """Generate reports and save results to file."""
    # Generate report
    report = checker.generate_report(updated_vex_data)
    checker.print_report_summary(report)

    # Save results
    print(f'\n💾 Saving results to {output_file}...')
    VexKernelCheckerBase.save_vex_file(updated_vex_data, output_file)
    print(f'✅ Results saved to {output_file}')

    # Performance stats
    if args.performance_stats:
        checker.print_performance_stats()

    # Final summary
    print_final_summary(report)


def run_analysis_workflow(args, output_file, perf_tracker):
    """Run the complete analysis workflow."""
    # Load and validate data
    vex_data, kernel_config = load_and_validate_data(args, perf_tracker)
    
    # Setup architecture detection
    arch, arch_config = setup_architecture_detection(kernel_config, perf_tracker)
    
    # Setup checker
    checker = setup_checker(args, arch)
    
    # Validate VEX data
    validate_and_show_vex_data(checker, vex_data)
    
    # Perform analysis
    updated_vex_data = perform_analysis(args, checker, vex_data, kernel_config, arch)
    
    # Save results and generate reports
    save_results_and_generate_reports(args, checker, updated_vex_data, output_file)


def main() -> int:
    """Entry point for the VEX Kernel Checker CLI."""
    # Parse arguments
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Validate input files
    if not validate_input_files(args):
        return 1

    # Set output file
    output_file = args.output if args.output else args.vex_file

    # Initialize performance tracker
    perf_tracker = PerformanceTracker()

    try:
        run_analysis_workflow(args, output_file, perf_tracker)
        return 0

    except KeyboardInterrupt:
        print('\nAnalysis interrupted by user')
        return 1
    except Exception as exception:
        print(f'Error during analysis: {exception}')
        if args.verbose:
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
