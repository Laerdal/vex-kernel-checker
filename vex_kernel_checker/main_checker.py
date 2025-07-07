#!/usr/bin/env python3
"""
Main Checker - Orchestrator for VEX Kernel Checker components

This module provides the main VexKernelChecker class that coordinates all other components.
"""

import os
import time
from typing import Dict, List, Optional, Any, Tuple

from .common import (
    VulnerabilityState, Justification, Response, 
    PerformanceTracker
)
from .base import VexKernelCheckerBase
from .cve_manager import CVEDataManager
from .patch_manager import PatchManager
from .config_analyzer import ConfigurationAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .architecture_manager import ArchitectureManager
from .report_generator import ReportGenerator


class VexKernelChecker(VexKernelCheckerBase):
    """
    Main orchestrator for VEX Kernel Checker functionality.
    
    This class coordinates all the component managers to provide a unified interface
    for vulnerability analysis.
    """
    
    def __init__(self, verbose: bool = False, api_key: Optional[str] = None,
                 edge_driver_path: Optional[str] = None, check_patches: bool = True,
                 analyze_all_cves: bool = False, arch: Optional[str] = None,
                 detailed_timing: bool = False, **kwargs):
        """Initialize the main checker with all components."""
        super().__init__(verbose=verbose, api_key=api_key, 
                        edge_driver_path=edge_driver_path, **kwargs)
        
        self.check_patches = check_patches
        self.analyze_all_cves = analyze_all_cves
        self.detailed_timing = detailed_timing
        
        # Initialize performance tracker
        self.perf_tracker = PerformanceTracker()
        
        # Initialize all component managers
        self.cve_manager = CVEDataManager(
            verbose=verbose, api_key=api_key, arch=arch,
            performance_tracker=self.perf_tracker, **kwargs
        )
        
        self.patch_manager = PatchManager(
            verbose=verbose, edge_driver_path=edge_driver_path, arch=arch,
            performance_tracker=self.perf_tracker, **kwargs
        )
        
        self.config_analyzer = ConfigurationAnalyzer(
            verbose=verbose, arch=arch, performance_tracker=self.perf_tracker, **kwargs
        )
        
        self.vulnerability_analyzer = VulnerabilityAnalyzer(
            verbose=verbose, arch=arch, performance_tracker=self.perf_tracker, 
            check_patches=check_patches, analyze_all_cves=analyze_all_cves, **kwargs
        )
        
        self.architecture_manager = ArchitectureManager(
            verbose=verbose, arch=arch, performance_tracker=self.perf_tracker, **kwargs
        )
        
        self.report_generator = ReportGenerator(
            verbose=verbose, arch=arch, performance_tracker=self.perf_tracker, **kwargs
        )
        
        if verbose:
            print("VexKernelChecker initialized with all components")

    def clear_all_caches(self) -> None:
        """Clear all caches in all components."""
        if self.verbose:
            print("Clearing all caches...")
        
        self.clear_caches()
        self.cve_manager.clear_caches()
        self.patch_manager.clear_caches()
        self.config_analyzer.clear_caches()
        self.vulnerability_analyzer.clear_caches()
        self.architecture_manager.clear_caches()
        self.report_generator.clear_caches()

    def validate_vex_data(self, vex_data: Dict) -> List[str]:
        """Validate VEX data format and return any issues."""
        issues = []
        
        if not isinstance(vex_data, dict):
            issues.append("VEX data is not a dictionary")
            return issues
        
        if 'vulnerabilities' not in vex_data:
            issues.append("No 'vulnerabilities' key found in VEX data")
            return issues
        
        vulnerabilities = vex_data['vulnerabilities']
        if not isinstance(vulnerabilities, list):
            issues.append("'vulnerabilities' is not a list")
            return issues
        
        if len(vulnerabilities) == 0:
            issues.append("No vulnerabilities found in VEX data")
        
        # Validate individual vulnerabilities
        for i, vuln in enumerate(vulnerabilities):
            if not isinstance(vuln, dict):
                issues.append(f"Vulnerability {i} is not a dictionary")
                continue
            
            if 'id' not in vuln:
                issues.append(f"Vulnerability {i} missing 'id' field")
            
            # Check for proper CVE ID format
            if 'id' in vuln and not vuln['id'].startswith('CVE-'):
                issues.append(f"Vulnerability {i} has invalid CVE ID format: {vuln['id']}")
        
        return issues

    def analyze_vulnerabilities(self, vex_data: Dict, kernel_config: List[str],
                              kernel_source_path: str, reanalyse: bool = False,
                              cve_id: Optional[str] = None) -> Dict:
        """
        Main vulnerability analysis workflow.
        
        Args:
            vex_data: VEX data dictionary
            kernel_config: List of kernel configuration options
            kernel_source_path: Path to kernel source directory
            reanalyse: Whether to reanalyze existing vulnerabilities
            cve_id: Specific CVE ID to analyze (if provided)
        
        Returns:
            Updated VEX data with analysis results
        """
        start_time = time.time()
        
        if self.verbose:
            print(f"Starting vulnerability analysis...")
            print(f"  Reanalyse: {reanalyse}")
            print(f"  Specific CVE: {cve_id if cve_id else 'All CVEs'}")
            print(f"  Check patches: {self.check_patches}")
            print(f"  Analyze all CVEs: {self.analyze_all_cves}")
        
        vulnerabilities = vex_data.get('vulnerabilities', [])
        if not vulnerabilities:
            if self.verbose:
                print("No vulnerabilities found in VEX data")
            return vex_data
        
        # Filter vulnerabilities to process
        vulns_to_process = []
        for vuln in vulnerabilities:
            # Filter by specific CVE ID if provided
            if cve_id and vuln.get('id') != cve_id:
                continue
            
            # Skip if already analyzed and not reanalyzing
            if not reanalyse and 'analysis' in vuln:
                continue
            
            vulns_to_process.append(vuln)
        
        if self.verbose:
            print(f"Processing {len(vulns_to_process)} vulnerabilities...")
        
        processed_count = 0
        updated_vex_data = vex_data.copy()
        start_time = time.time()
        
        for i, vuln in enumerate(vulns_to_process):
            cve_id_current = vuln.get('id', f'UNKNOWN-{i}')
            
            # Progress reporting
            if len(vulns_to_process) > 5:  # Show progress for more than 5 CVEs
                progress = ((i + 1) / len(vulns_to_process)) * 100
                elapsed_time = time.time() - start_time
                
                if elapsed_time > 0 and i > 0:
                    avg_time_per_cve = elapsed_time / i
                    remaining_cves = len(vulns_to_process) - i
                    eta_seconds = remaining_cves * avg_time_per_cve
                    
                    if eta_seconds > 60:
                        eta_str = f"{int(eta_seconds // 60)}m{int(eta_seconds % 60)}s"
                    else:
                        eta_str = f"{int(eta_seconds)}s"
                        
                    print(f"\r🔍 Progress: {i+1}/{len(vulns_to_process)} ({progress:.1f}%) - Current: {cve_id_current} - ETA: {eta_str}", end='', flush=True)
                else:
                    print(f"\r🔍 Progress: {i+1}/{len(vulns_to_process)} ({progress:.1f}%) - Current: {cve_id_current}", end='', flush=True)
            elif self.verbose:
                print(f"\n📋 Processing {cve_id_current} ({i+1}/{len(vulns_to_process)})...")
            
            try:
                # Analyze this vulnerability
                analysis_result = self._analyze_single_vulnerability(
                    vuln, kernel_config, kernel_source_path
                )
                
                # Only add analysis if it's not a filter result (None means skip)
                if analysis_result is not None:
                    # Update vulnerability with analysis
                    vuln_index = None
                    for idx, orig_vuln in enumerate(updated_vex_data['vulnerabilities']):
                        if orig_vuln.get('id') == cve_id_current:
                            vuln_index = idx
                            break
                    
                    if vuln_index is not None:
                        updated_vex_data['vulnerabilities'][vuln_index]['analysis'] = analysis_result
                        processed_count += 1
                else:
                    if self.verbose:
                        print(f"  Skipping {cve_id_current} - not kernel related or analysis failed")
                    
                    # If reanalyzing, remove existing analysis for skipped CVEs
                    if reanalyse:
                        vuln_index = None
                        for idx, orig_vuln in enumerate(updated_vex_data['vulnerabilities']):
                            if orig_vuln.get('id') == cve_id_current:
                                vuln_index = idx
                                break
                        
                        if vuln_index is not None and 'analysis' in updated_vex_data['vulnerabilities'][vuln_index]:
                            del updated_vex_data['vulnerabilities'][vuln_index]['analysis']
                            if self.verbose:
                                print(f"    Removed existing analysis from {cve_id_current}")
                
            except Exception as e:
                if self.verbose:
                    print(f"  Error processing {cve_id_current}: {e}")
                # Do NOT add error analysis - leave CVE unprocessed
                # This allows for manual review or retry later
        
        # Print newline after progress reporting
        if len(vulns_to_process) > 5:
            print()  # New line after progress reporting
        
        # Update metadata
        if 'metadata' not in updated_vex_data:
            updated_vex_data['metadata'] = {}
        
        updated_vex_data['metadata'].update({
            'last_analysis': self.get_current_timestamp(),
            'processed_count': processed_count,
            'tool_version': '2.0',
            'analysis_method': 'kernel_config_analysis'
        })
        
        total_time = time.time() - start_time
        if self.verbose:
            print(f"\n✅ Analysis completed in {total_time:.2f}s")
            print(f"   Processed: {processed_count} vulnerabilities")
        
        return updated_vex_data

    def _analyze_single_vulnerability(self, vuln: Dict, kernel_config: List[str],
                                    kernel_source_path: str) -> Optional[Dict]:
        """
        Analyze a single vulnerability using the VulnerabilityAnalyzer.
        
        Returns:
            Dict with analysis results if CVE should be analyzed
            None if CVE should be skipped (not kernel related or analysis failed)
        """
        try:
            # Use the vulnerability analyzer to perform the analysis
            analysis_result = self.vulnerability_analyzer.analyze_cve(
                cve=vuln,
                kernel_config=kernel_config,
                kernel_source_path=kernel_source_path,
                cve_manager=self.cve_manager,
                patch_manager=self.patch_manager,
                config_analyzer=self.config_analyzer
            )
            
            # If analysis_result is None, it means either:
            # 1. CVE is not kernel-related (and should be skipped)
            # 2. Analysis failed (and CVE should remain unprocessed)
            if analysis_result is None:
                return None
            
            # Convert VulnerabilityAnalysis object to dictionary
            return analysis_result.to_dict()
            
        except Exception as e:
            cve_id = vuln.get('id', 'UNKNOWN')
            if self.verbose:
                print(f"  Error analyzing {cve_id}: {e}")
            # Return None to indicate analysis failed - CVE remains unprocessed
            return None

    def generate_report(self, vex_data: Dict) -> Dict:
        """Generate analysis report."""
        return self.report_generator.generate_summary_report(vex_data)

    def print_report_summary(self, report: Dict) -> None:
        """Print report summary."""
        self.report_generator.print_summary_report(report)

    def print_performance_stats(self) -> None:
        """Print performance statistics."""
        # Simple implementation using available performance data
        print("\n📊 Performance Statistics:")
        print("="*50)
        
        # Show cache statistics
        print(f"Cache hits: {self._cache_hits}")
        print(f"Cache misses: {self._cache_misses}")
        
        # Show processed CVEs
        print(f"Processed CVEs: {len(self._processed_cves)}")
        
        print("="*50)
