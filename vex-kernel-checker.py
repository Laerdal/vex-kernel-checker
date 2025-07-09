#!/usr/bin/env python3
"""
VEX Kernel Checker - Main CLI Application.

This script provides the main command-line interface for the VEX Kernel Checker
using the refactored modular components.

MIT License - See LICENSE file for details.
"""

# flake8: noqa: SC200

import argparse
import configparser
import json
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
    configure_logging,
    get_logger,
)

import logging

def setup_logging(verbose: bool, log_file: Optional[str] = None):
    """Setup structured logging with enhanced verbose mode."""
    # Use centralized logging configuration
    configure_logging(verbose, log_file)
    
    # Get logger for this module
    logger = get_logger(__name__)
    
    if verbose:
        logger.debug("Verbose logging enabled for main CLI")
    
    return logger


def load_config_file(config_path: str) -> Dict:
    """
    Load configuration from file.
    
    Supports both INI format (.ini, .cfg, .config) and JSON format (.json).
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Dictionary containing configuration options
        
    Raises:
        SystemExit: If configuration file cannot be loaded or parsed
    """
    logger = get_logger(__name__)
    
    if not os.path.exists(config_path):
        logger.error(f'Configuration file not found: {config_path}')
        print(f'Error: Configuration file not found: {config_path}')
        sys.exit(1)
    
    config = {}
    
    try:
        # Determine file format based on extension
        _, ext = os.path.splitext(config_path.lower())
        logger.debug(f"Detected configuration file format: {ext}")
        
        if ext == '.json':
            # JSON format
            logger.debug("Loading JSON configuration file")
            with open(config_path, 'r', encoding='utf-8') as f:
                json_config = json.load(f)
                
            # Flatten the JSON structure to match command-line arguments
            for key, value in json_config.items():
                # Convert underscores to hyphens for CLI compatibility
                cli_key = key.replace('_', '-')
                
                # Expand paths for file/directory related options
                if cli_key in ['vex-file', 'kernel-config', 'kernel-source', 'output', 'log-file', 'edge-driver']:
                    # Expand user home directory (~) and convert to absolute path
                    expanded_value = os.path.expanduser(str(value))
                    # Convert relative paths to absolute (relative to config file location)
                    if not os.path.isabs(expanded_value):
                        config_dir = os.path.dirname(os.path.abspath(config_path))
                        expanded_value = os.path.join(config_dir, expanded_value)
                    config[cli_key] = expanded_value
                    logger.debug(f"Expanded path for {cli_key}: {expanded_value}")
                else:
                    config[cli_key] = value
                
        elif ext in ['.ini', '.cfg', '.config']:
            # INI format
            logger.debug("Loading INI configuration file")
            parser = configparser.ConfigParser()
            parser.read(config_path)
            
            # Use the 'vex-kernel-checker' section if it exists, otherwise use DEFAULT
            section_name = 'vex-kernel-checker' if 'vex-kernel-checker' in parser else 'DEFAULT'
            logger.debug(f"Using configuration section: {section_name}")
            
            for key, value in parser[section_name].items():
                # Convert underscores to hyphens for CLI compatibility
                cli_key = key.replace('_', '-')
                
                # Handle boolean values
                if value.lower() in ['true', 'yes', '1', 'on']:
                    config[cli_key] = True
                elif value.lower() in ['false', 'no', '0', 'off']:
                    config[cli_key] = False
                else:
                    # Expand paths for file/directory related options
                    if cli_key in ['vex-file', 'kernel-config', 'kernel-source', 'output', 'log-file', 'edge-driver']:
                        # Expand user home directory (~) and convert to absolute path
                        expanded_value = os.path.expanduser(value)
                        # Convert relative paths to absolute (relative to config file location)
                        if not os.path.isabs(expanded_value):
                            config_dir = os.path.dirname(os.path.abspath(config_path))
                            expanded_value = os.path.join(config_dir, expanded_value)
                        config[cli_key] = expanded_value
                        logger.debug(f"Expanded path for {cli_key}: {expanded_value}")
                    else:
                        config[cli_key] = value
                    
        else:
            logger.error(f'Unsupported configuration file format: {ext}')
            print(f'Error: Unsupported configuration file format: {ext}')
            print('Supported formats: .json, .ini, .cfg, .config')
            sys.exit(1)
        
        logger.info(f"Successfully loaded configuration with {len(config)} options")
        logger.debug(f"Configuration keys: {list(config.keys())}")
            
    except json.JSONDecodeError as e:
        logger.error(f'Error parsing JSON configuration file: {e}')
        print(f'Error parsing JSON configuration file: {e}')
        sys.exit(1)
    except configparser.Error as e:
        logger.error(f'Error parsing INI configuration file: {e}')
        print(f'Error parsing INI configuration file: {e}')
        sys.exit(1)
    except Exception as e:
        logger.error(f'Error loading configuration file: {e}')
        print(f'Error loading configuration file: {e}')
        sys.exit(1)
    
    return config


def merge_config_with_args(config: Dict, args: argparse.Namespace) -> argparse.Namespace:
    """
    Merge configuration file values with command-line arguments.
    
    Command-line arguments take precedence over configuration file values.
    
    Args:
        config: Configuration dictionary from file
        args: Parsed command-line arguments
        
    Returns:
        Updated argument namespace
    """
    logger = get_logger(__name__)
    
    # Create a copy of args to avoid modifying the original
    merged_args = argparse.Namespace(**vars(args))
    
    # Only apply config values if the command-line argument is not set
    for key, value in config.items():
        # Convert hyphens to underscores for attribute access
        attr_key = key.replace('-', '_')
        
        # Skip if the attribute doesn't exist on args (invalid config option)
        if not hasattr(merged_args, attr_key):
            logger.warning(f'Unknown configuration option: {key}')
            print(f'Warning: Unknown configuration option: {key}')
            continue
            
        # Only use config value if command-line argument is not set/is default
        current_value = getattr(merged_args, attr_key)
        
        # For boolean flags, only set if current value is False
        if isinstance(current_value, bool):
            if not current_value and value:
                setattr(merged_args, attr_key, value)
                logger.debug(f"Set {attr_key} from config: {value}")
        # For other values, only set if current value is None or empty
        elif current_value is None or current_value == '':
            setattr(merged_args, attr_key, value)
            logger.debug(f"Set {attr_key} from config: {value}")
    
    return merged_args


def create_sample_config_file(config_path: str, format_type: str = 'ini') -> None:
    """
    Create a sample configuration file to help users get started.
    
    Args:
        config_path: Path where to create the sample config file
        format_type: Format type ('ini' or 'json')
    """
    if format_type == 'json':
        sample_config = {
            "vex_file": "/path/to/your/vex-file.json",
            "kernel_config": "/path/to/your/.config", 
            "kernel_source": "/path/to/your/kernel/source",
            "api_key": "your-nvd-api-key",
            "edge_driver": "/path/to/msedgedriver",
            "verbose": True,
            "reanalyse": False,
            "config_only": False,
            "analyze_all_cves": False,
            "performance_stats": True,
            "detailed_timing": False,
            "clear_cache": False
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2)
            
    else:  # INI format
        sample_config = """[vex-kernel-checker]
# Required arguments
vex_file = /path/to/your/vex-file.json
kernel_config = /path/to/your/.config
kernel_source = /path/to/your/kernel/source

# Optional arguments
output = 
log_file = 
api_key = your-nvd-api-key
edge_driver = /path/to/msedgedriver
cve_id = 

# Boolean flags (true/false)
verbose = true
reanalyse = false
config_only = false
analyze_all_cves = false
performance_stats = true
detailed_timing = false
clear_cache = false
"""
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write(sample_config)
    
    print(f'Sample configuration file created: {config_path}')
    print(f'Please edit this file with your specific settings.')


def validate_input_files(args) -> bool:
    """Validate that all required input files exist."""
    logger = get_logger(__name__)
    
    # Check if required arguments are provided
    if not args.vex_file:
        logger.error('--vex-file is required')
        print('Error: --vex-file is required')
        return False
    if not args.kernel_config:
        logger.error('--kernel-config is required')
        print('Error: --kernel-config is required')
        return False
    if not args.kernel_source:
        logger.error('--kernel-source is required')
        print('Error: --kernel-source is required')
        return False
    
    logger.debug("Validating input files existence")
    
    validations = [
        (args.vex_file, "VEX file"),
        (args.kernel_config, "Kernel config file"),
        (args.kernel_source, "Kernel source directory")
    ]
    
    for file_path, description in validations:
        if not os.path.exists(file_path):
            logger.error(f'{description} not found: {file_path}')
            print(f'Error: {description} not found: {file_path}')
            return False
        else:
            logger.debug(f'{description} found: {file_path}')
    
    # Additional validation for file types/formats
    if not args.vex_file.endswith(('.json', '.cdx')):
        logger.warning(f'VEX file should be JSON or CDX format: {args.vex_file}')
        print(f'Warning: VEX file should be JSON or CDX format: {args.vex_file}')
    
    logger.info("All input files validated successfully")
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
            'Use --reanalyse to re-analyze CVEs that already have results.\n\n'
            'Configuration files can be used to store commonly used options.\n'
            'Supported formats: .json, .ini, .cfg, .config'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Configuration file options
    parser.add_argument(
        '--config', 
        help='Path to configuration file (supports .json, .ini, .cfg, .config formats)'
    )
    parser.add_argument(
        '--create-config',
        help='Create a sample configuration file at the specified path and exit'
    )
    parser.add_argument(
        '--config-format',
        choices=['ini', 'json'],
        default='ini',
        help='Format for created configuration file (default: ini)'
    )

    # Required arguments (can be provided via config file)
    parser.add_argument('--vex-file', help='Path to VEX JSON file')
    parser.add_argument('--kernel-config', help='Path to kernel config file (.config)')
    parser.add_argument('--kernel-source', help='Path to kernel source directory')

    # Optional arguments
    parser.add_argument('--output', help='Output file path (default: update VEX file in place)')
    parser.add_argument('--log-file', help='Log file path (default: no logging)')
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
    logger = get_logger(__name__)
    
    # Load VEX data
    logger.info(f'Loading VEX data from {args.vex_file}...')
    perf_tracker.start_timer('load_vex_data')
    print(f'Loading VEX data from {args.vex_file}...')
    vex_data = VexKernelCheckerBase.load_vex_file(args.vex_file)
    perf_tracker.end_timer('load_vex_data')
    logger.debug(f"Loaded VEX data with {len(vex_data.get('vulnerabilities', []))} vulnerabilities")

    # Load kernel config
    logger.info(f'Loading kernel configuration from {args.kernel_config}...')
    perf_tracker.start_timer('load_kernel_config')
    print(f'Loading kernel configuration from {args.kernel_config}...')
    kernel_config = VexKernelCheckerBase.load_kernel_config(args.kernel_config)
    perf_tracker.end_timer('load_kernel_config')

    logger.info(f'Loaded {len(kernel_config)} configuration options')
    print(f'Loaded {len(kernel_config)} configuration options')

    return vex_data, kernel_config


def setup_architecture_detection(kernel_config, perf_tracker: PerformanceTracker):
    """Extract and validate architecture from kernel configuration."""
    logger = get_logger(__name__)
    
    logger.debug("Extracting architecture from kernel configuration")
    perf_tracker.start_timer('extract_architecture')
    arch, arch_config = VexKernelCheckerBase.extract_arch_from_config(kernel_config)
    perf_tracker.end_timer('extract_architecture')

    if arch and arch_config:
        logger.info(f'Detected architecture: {arch} ({arch_config})')
        print(f'Detected architecture: {arch} ({arch_config})')
    else:
        logger.warning('Could not detect architecture from kernel configuration')
        print('Warning: Could not detect architecture from kernel configuration')
        print('This may affect the accuracy of vulnerability analysis')

    return arch, arch_config


def setup_checker(args, arch):
    """Initialize the VEX Kernel Checker with provided arguments."""
    logger = get_logger(__name__)
    
    disable_patch_checking = args.config_only
    
    logger.info('Initializing VEX Kernel Checker...')
    logger.debug(f"Patch checking: {'disabled' if disable_patch_checking else 'enabled'}")
    logger.debug(f"Architecture: {arch}")
    logger.debug(f"Analyze all CVEs: {args.analyze_all_cves}")
    logger.debug(f"API key provided: {bool(args.api_key)}")
    logger.debug(f"Edge driver path: {args.edge_driver}")
    
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
        logger.info('Clearing caches...')
        print('Clearing caches...')
        checker.clear_all_caches()

    return checker


def validate_and_show_vex_data(checker, vex_data):
    """Validate VEX data and show any issues."""
    logger = get_logger(__name__)
    
    logger.debug("Validating VEX data structure")
    validation_issues = checker.validate_vex_data(vex_data)
    
    if validation_issues:
        logger.warning(f"Found {len(validation_issues)} VEX data validation issues")
        print('VEX data validation warnings:')
        for issue in validation_issues[:3]:
            logger.warning(f"VEX validation issue: {issue}")
            print(f'  ⚠️  {issue}')
        if len(validation_issues) > 3:
            logger.warning(f"... and {len(validation_issues) - 3} more validation issues")
            print(f'  ... and {len(validation_issues) - 3} more issues')
        print()
    else:
        logger.info("VEX data validation completed successfully")
        logger.debug("No validation issues found")


def perform_analysis(args, checker, vex_data, kernel_config, arch):
    """Execute the vulnerability analysis and return results."""
    logger = get_logger(__name__)
    
    logger.info("Starting vulnerability analysis")
    print('\n' + '=' * 60)
    print('🚀 STARTING VULNERABILITY ANALYSIS')
    print('=' * 60)

    # Show analysis overview
    print_analysis_overview(
        vex_data, kernel_config, arch, args.config_only, args.api_key
    )

    logger.debug(f"Analysis parameters: reanalyse={args.reanalyse}, cve_id={args.cve_id}")
    logger.debug(f"Kernel source path: {args.kernel_source}")
    
    start_time = time.time()

    updated_vex_data = checker.analyze_vulnerabilities(
        vex_data=vex_data,
        kernel_config=kernel_config,
        kernel_source_path=args.kernel_source,
        reanalyse=args.reanalyse,
        cve_id=args.cve_id,
    )

    analysis_time = time.time() - start_time
    logger.info(f"Analysis completed in {analysis_time:.2f} seconds")
    
    print('\n' + '=' * 60)
    print('✅ ANALYSIS COMPLETED')
    print('=' * 60)
    print(f'⏱️  Total analysis time: {analysis_time:.2f} seconds')

    total_vulns = len(vex_data.get('vulnerabilities', []))
    if analysis_time > 0:
        performance_rate = total_vulns / analysis_time
        logger.info(f"Analysis performance: {performance_rate:.1f} CVEs/second")
        print(f'📊 Performance: {performance_rate:.1f} CVEs/second')
    print()

    return updated_vex_data


def save_results_and_generate_reports(args, checker, updated_vex_data, output_file):
    """Generate reports and save results to file."""
    logger = get_logger(__name__)
    
    logger.info("Generating vulnerability report")
    # Generate report
    report = checker.generate_report(updated_vex_data)
    checker.print_report_summary(report)
    
    logger.debug(f"Report summary: {report}")

    # Save results
    logger.info(f'Saving results to {output_file}')
    print(f'\n💾 Saving results to {output_file}...')
    VexKernelCheckerBase.save_vex_file(updated_vex_data, output_file)
    print(f'✅ Results saved to {output_file}')

    # Performance stats
    if args.performance_stats:
        logger.debug("Displaying performance statistics")
        checker.print_performance_stats()

    # Final summary
    print_final_summary(report)


def run_analysis_workflow(args, output_file, perf_tracker):
    """Run the complete analysis workflow."""
    logger = get_logger(__name__)
    
    logger.info("Starting analysis workflow")
    logger.debug(f"Output file: {output_file}")
    
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
    
    logger.info("Analysis workflow completed successfully")


def main() -> int:
    """Entry point for the VEX Kernel Checker CLI."""
    
    # Parse arguments
    parser = setup_argument_parser()
    args = parser.parse_args()

    # Handle configuration file creation
    if args.create_config:
        create_sample_config_file(args.create_config, args.config_format)
        return 0

    # Load configuration file if specified
    config = {}
    if args.config:
        logger = get_logger(__name__)
        logger.info(f'Loading configuration from: {args.config}')
        config = load_config_file(args.config)
        
        # Merge configuration with command-line arguments
        args = merge_config_with_args(config, args)
        
        logger.info('Configuration loaded and merged with command-line arguments')
        if args.verbose:
            logger.debug(f"Configuration values: {config}")
            logger.debug(f"Merged arguments: {vars(args)}")

    logger = setup_logging(args.verbose, args.log_file)

    # Get logger for this module
    if not logger:
        logger = get_logger(__name__)
    
    if args.verbose:
        logger.debug("Starting VEX Kernel Checker with verbose logging enabled")
        logger.debug(f"Command line arguments: {vars(args)}")

    # Validate input files
    if not validate_input_files(args):
        return 1

    # Set output file
    output_file = args.output if args.output else args.vex_file

    # Initialize performance tracker
    perf_tracker = PerformanceTracker()

    try:
        run_analysis_workflow(args, output_file, perf_tracker)
        logger.info("VEX Kernel Checker completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.warning("Analysis interrupted by user")
        print('\nAnalysis interrupted by user')
        return 1
    except Exception as exception:
        logger.error(f'Error during analysis: {exception}')
        print(f'Error during analysis: {exception}')
        if args.verbose:
            logger.debug("Full traceback:", exc_info=True)
            traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
