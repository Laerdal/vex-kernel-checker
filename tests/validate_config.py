#!/usr/bin/env python3
"""
Configuration validation script for VEX Kernel Checker.

This script validates the user's environment and configuration files
to ensure the VEX Kernel Checker can run successfully.
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Tuple, Optional

def check_python_version() -> Tuple[bool, str]:
    """Check if Python version is compatible."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        return False, f"Python 3.7+ required, found {version.major}.{version.minor}"
    return True, f"Python {version.major}.{version.minor}.{version.micro}"

def check_required_packages() -> Tuple[bool, List[str]]:
    """Check if all required Python packages are installed."""
    required_packages = [
        ('selenium', 'selenium'),
        ('requests', 'requests'),
        ('json', 'json'),  # Built-in, should always be available
    ]
    
    missing = []
    installed = []
    
    for package_name, import_name in required_packages:
        try:
            __import__(import_name)
            installed.append(package_name)
        except ImportError:
            missing.append(package_name)
    
    return len(missing) == 0, missing

def check_vex_file(vex_file_path: str) -> Tuple[bool, List[str]]:
    """Validate VEX file format and content."""
    issues = []
    
    if not os.path.exists(vex_file_path):
        return False, [f"VEX file not found: {vex_file_path}"]
    
    try:
        with open(vex_file_path, 'r') as f:
            vex_data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"Invalid JSON format: {e}"]
    except Exception as e:
        return False, [f"Error reading VEX file: {e}"]
    
    # Check required structure
    if 'vulnerabilities' not in vex_data:
        issues.append("Missing 'vulnerabilities' field in VEX data")
    elif not isinstance(vex_data['vulnerabilities'], list):
        issues.append("'vulnerabilities' field must be a list")
    else:
        vulns = vex_data['vulnerabilities']
        
        if len(vulns) == 0:
            issues.append("No vulnerabilities found in VEX data")
        
        # Check individual vulnerability entries
        for i, vuln in enumerate(vulns[:10]):  # Check first 10
            if not isinstance(vuln, dict):
                issues.append(f"Vulnerability {i}: not a dictionary")
                continue
            
            if 'id' not in vuln:
                issues.append(f"Vulnerability {i}: missing 'id' field")
            elif not vuln['id'].startswith('CVE-'):
                issues.append(f"Vulnerability {i}: ID should start with 'CVE-', found '{vuln['id']}'")
            
            # Check optional fields
            if 'severity' in vuln and vuln['severity'] not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN']:
                issues.append(f"Vulnerability {i}: invalid severity '{vuln['severity']}'")
    
    return len(issues) == 0, issues

def check_kernel_config(config_file_path: str) -> Tuple[bool, List[str]]:
    """Validate kernel configuration file."""
    issues = []
    
    if not os.path.exists(config_file_path):
        return False, [f"Kernel config file not found: {config_file_path}"]
    
    try:
        with open(config_file_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        return False, [f"Error reading kernel config file: {e}"]
    
    config_count = 0
    enabled_count = 0
    
    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue
        
        # Check for valid config format
        if '=' not in line:
            issues.append(f"Line {line_num}: Invalid config format: {line}")
            continue
        
        config_name, config_value = line.split('=', 1)
        config_count += 1
        
        # Check config name format
        if not config_name.startswith('CONFIG_'):
            issues.append(f"Line {line_num}: Config name should start with 'CONFIG_': {config_name}")
        
        # Count enabled configs
        if config_value in ['y', 'm']:
            enabled_count += 1
    
    if config_count == 0:
        issues.append("No configuration options found")
    
    if enabled_count == 0:
        issues.append("No enabled configuration options found")
    
    # Add informational messages
    if not issues:
        issues.append(f"INFO: Found {config_count} total configs, {enabled_count} enabled")
    
    return len([i for i in issues if not i.startswith('INFO:')]) == 0, issues

def check_kernel_source(kernel_source_path: str) -> Tuple[bool, List[str]]:
    """Validate kernel source directory structure."""
    issues = []
    
    if not os.path.exists(kernel_source_path):
        return False, [f"Kernel source directory not found: {kernel_source_path}"]
    
    if not os.path.isdir(kernel_source_path):
        return False, [f"Kernel source path is not a directory: {kernel_source_path}"]
    
    # Check for expected kernel directory structure
    expected_dirs = [
        'drivers',
        'fs',
        'net',
        'kernel',
        'mm'
    ]
    
    found_dirs = []
    for expected_dir in expected_dirs:
        dir_path = os.path.join(kernel_source_path, expected_dir)
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            found_dirs.append(expected_dir)
    
    if len(found_dirs) == 0:
        issues.append("No expected kernel directories found (drivers, fs, net, kernel, mm)")
    elif len(found_dirs) < 3:
        issues.append(f"Only found {len(found_dirs)} of {len(expected_dirs)} expected directories: {found_dirs}")
    
    # Check for Makefiles
    makefile_count = 0
    for root, dirs, files in os.walk(kernel_source_path):
        for file in files:
            if file in ['Makefile', 'Kbuild']:
                makefile_count += 1
        
        # Limit search depth to avoid long searches
        if makefile_count > 100 or len(root.split(os.sep)) > len(kernel_source_path.split(os.sep)) + 5:
            break
    
    if makefile_count == 0:
        issues.append("No Makefiles found in kernel source")
    else:
        issues.append(f"INFO: Found {makefile_count} Makefiles")
    
    return len([i for i in issues if not i.startswith('INFO:')]) == 0, issues

def check_webdriver_setup(webdriver_path: Optional[str] = None) -> Tuple[bool, List[str]]:
    """Check WebDriver setup if provided."""
    issues = []
    
    if not webdriver_path:
        issues.append("INFO: WebDriver not configured (patch checking will be disabled)")
        return True, issues
    
    if not os.path.exists(webdriver_path):
        return False, [f"WebDriver not found: {webdriver_path}"]
    
    if not os.path.isfile(webdriver_path):
        return False, [f"WebDriver path is not a file: {webdriver_path}"]
    
    # Check if executable
    if not os.access(webdriver_path, os.X_OK):
        issues.append("WebDriver file is not executable")
    
    # Try to check WebDriver version (optional)
    try:
        result = subprocess.run([webdriver_path, '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            version_info = result.stdout.strip()
            issues.append(f"INFO: WebDriver version: {version_info}")
        else:
            issues.append("Warning: Could not determine WebDriver version")
    except subprocess.TimeoutExpired:
        issues.append("Warning: WebDriver version check timed out")
    except Exception as e:
        issues.append(f"Warning: WebDriver version check failed: {e}")
    
    return len([i for i in issues if not i.startswith(('INFO:', 'Warning:'))]) == 0, issues

def check_tool_accessibility() -> Tuple[bool, List[str]]:
    """Check if the VEX Kernel Checker tool is accessible."""
    issues = []
    
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    tool_path = script_dir.parent / "../vex-kernel-checker.py"
    
    if not tool_path.exists():
        return False, [f"VEX Kernel Checker not found at: {tool_path}"]
    
    # Try to import the tool
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("vex_kernel_checker", tool_path)
        if spec is None or spec.loader is None:
            return False, ["Error: Could not create module spec for VEX Kernel Checker"]
        vkc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vkc_module)
        issues.append("INFO: VEX Kernel Checker imports successfully")
    except Exception as e:
        return False, [f"Error importing VEX Kernel Checker: {e}"]
    
    return True, issues

def validate_configuration(vex_file: str, kernel_config: str, kernel_source: str, 
                         webdriver_path: Optional[str] = None, api_key: Optional[str] = None) -> Dict:
    """Run complete configuration validation."""
    results = {
        'overall_status': True,
        'checks': {}
    }
    
    checks = [
        ('python_version', lambda: check_python_version()),
        ('required_packages', lambda: check_required_packages()),
        ('tool_accessibility', lambda: check_tool_accessibility()),
        ('vex_file', lambda: check_vex_file(vex_file)),
        ('kernel_config', lambda: check_kernel_config(kernel_config)),
        ('kernel_source', lambda: check_kernel_source(kernel_source)),
        ('webdriver_setup', lambda: check_webdriver_setup(webdriver_path)),
    ]
    
    for check_name, check_func in checks:
        try:
            success, messages = check_func()
            results['checks'][check_name] = {
                'success': success,
                'messages': messages
            }
            
            if not success:
                results['overall_status'] = False
                
        except Exception as e:
            results['checks'][check_name] = {
                'success': False,
                'messages': [f"Check failed with error: {e}"]
            }
            results['overall_status'] = False
    
    # Additional checks for API key
    if api_key:
        if len(api_key) < 10:
            results['checks']['api_key'] = {
                'success': False,
                'messages': ['API key appears to be too short']
            }
            results['overall_status'] = False
        else:
            results['checks']['api_key'] = {
                'success': True,
                'messages': ['INFO: API key provided']
            }
    else:
        results['checks']['api_key'] = {
            'success': True,
            'messages': ['INFO: No API key provided (patch checking will be disabled)']
        }
    
    return results

def print_validation_results(results: Dict, verbose: bool = True):
    """Print validation results in a user-friendly format."""
    print("VEX Kernel Checker Configuration Validation")
    print("=" * 50)
    
    if results['overall_status']:
        print("✅ Overall Status: PASS")
    else:
        print("❌ Overall Status: FAIL")
    
    print("\nDetailed Results:")
    
    for check_name, check_result in results['checks'].items():
        check_display_name = check_name.replace('_', ' ').title()
        
        if check_result['success']:
            print(f"✅ {check_display_name}")
        else:
            print(f"❌ {check_display_name}")
        
        if verbose or not check_result['success']:
            for message in check_result['messages']:
                if message.startswith('INFO:'):
                    print(f"   ℹ️  {message[5:]}")
                elif message.startswith('Warning:'):
                    print(f"   ⚠️  {message[8:]}")
                else:
                    print(f"   • {message}")
    
    print("\nRecommendations:")
    
    if not results['overall_status']:
        failed_checks = [name for name, result in results['checks'].items() if not result['success']]
        print("❌ Fix the following issues before running VEX Kernel Checker:")
        for check in failed_checks:
            print(f"   • {check.replace('_', ' ').title()}")
    else:
        print("✅ Your configuration appears to be valid!")
        
        # Check what functionality is available
        has_webdriver = results['checks']['webdriver_setup']['success'] and \
                       not any('not configured' in msg for msg in results['checks']['webdriver_setup']['messages'])
        has_api_key = 'api_key' in results['checks'] and \
                     results['checks']['api_key']['success'] and \
                     not any('No API key' in msg for msg in results['checks']['api_key']['messages'])
        
        if has_webdriver and has_api_key:
            print("✅ Full functionality available (patch checking enabled)")
        else:
            print("⚠️  Limited functionality (config-only analysis)")
            if not has_webdriver:
                print("   • WebDriver not configured - patch fetching disabled")
            if not has_api_key:
                print("   • API key not provided - CVE details fetching disabled")

def main():
    """Main entry point for validation script."""
    parser = argparse.ArgumentParser(
        description="Validate VEX Kernel Checker configuration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_config.py --vex-file data.vex --kernel-config .config --kernel-source /path/to/kernel

  python validate_config.py --vex-file data.vex --kernel-config .config --kernel-source /path/to/kernel \\
                            --webdriver /path/to/msedgedriver --api-key your-nvd-api-key
        """
    )
    
    parser.add_argument('--vex-file', required=True, help='Path to VEX JSON file')
    parser.add_argument('--kernel-config', required=True, help='Path to kernel config file')
    parser.add_argument('--kernel-source', required=True, help='Path to kernel source directory')
    parser.add_argument('--webdriver', help='Path to Edge WebDriver executable')
    parser.add_argument('--api-key', help='NVD API key')
    parser.add_argument('--quiet', '-q', action='store_true', help='Show only failures and overall status')
    parser.add_argument('--json-output', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Run validation
    results = validate_configuration(
        args.vex_file, 
        args.kernel_config, 
        args.kernel_source,
        args.webdriver,
        args.api_key
    )
    
    # Print results
    print_validation_results(results, verbose=not args.quiet)
    
    # Save JSON output if requested
    if args.json_output:
        with open(args.json_output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.json_output}")
    
    # Return appropriate exit code
    return 0 if results['overall_status'] else 1

if __name__ == '__main__':
    sys.exit(main())
