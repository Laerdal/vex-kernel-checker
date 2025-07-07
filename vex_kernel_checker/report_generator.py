#!/usr/bin/env python3
"""
Report Generator for VEX Kernel Checker.

This module handles generating various types of reports:
- Summary reports with statistics
- Detailed analysis reports
- VEX format output
- Performance reports
"""

import json
import time
from typing import Dict, List, Optional, Any
from .base import VexKernelCheckerBase
from .common import VulnerabilityState, Justification, Response, timed_method


class ReportGenerator(VexKernelCheckerBase):
    """Generates reports and summaries for vulnerability analysis."""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._report_data = {}
        self._statistics = {}
    
    @timed_method
    def generate_summary_report(self, vex_data: Dict) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report.
        
        Args:
            vex_data: VEX document data
            
        Returns:
            Dictionary with summary statistics and analysis
        """
        vulnerabilities = vex_data.get('vulnerabilities', [])
        
        # Initialize report structure
        report = {
            'total': len(vulnerabilities),
            'resolved': 0,
            'resolved_with_pedigree': 0,
            'exploitable': 0,
            'in_triage': 0,
            'false_positive': 0,
            'not_affected': 0,
            'summary': {},
            'vulnerabilities': {},
            'by_severity': {},
            'by_justification': {},
            'analysis_coverage': 0.0,
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        
        # Analyze each vulnerability
        for vuln in vulnerabilities:
            cve_id = vuln.get('id', 'unknown')
            analysis = vuln.get('analysis', {})
            state = analysis.get('state', '')
            justification = analysis.get('justification', '')
            detail = analysis.get('detail', '')
            
            # Count by state using CycloneDX v1.6 states
            if state == VulnerabilityState.RESOLVED.value:
                report['resolved'] += 1
            elif state == VulnerabilityState.RESOLVED_WITH_PEDIGREE.value:
                report['resolved_with_pedigree'] += 1
            elif state == VulnerabilityState.EXPLOITABLE.value:
                report['exploitable'] += 1
            elif state == VulnerabilityState.IN_TRIAGE.value:
                report['in_triage'] += 1
            elif state == VulnerabilityState.FALSE_POSITIVE.value:
                report['false_positive'] += 1
            elif state == VulnerabilityState.NOT_AFFECTED.value:
                report['not_affected'] += 1
            elif state == '':
                # Empty state means CVE was not processed/analyzed - count as in_triage for reporting
                report['in_triage'] += 1
            else:
                # Default unknown states to in_triage
                report['in_triage'] += 1
            
            # Store vulnerability details
            vuln_details = {
                'state': state,
                'justification': justification,
                'detail': detail,
                'severity': vuln.get('severity', 'unknown'),
                'description': vuln.get('description', '')
            }
            report['vulnerabilities'][cve_id] = vuln_details
            
            # Count by severity
            severity = vuln.get('severity', 'unknown').upper()
            if severity not in report['by_severity']:
                report['by_severity'][severity] = 0
            report['by_severity'][severity] += 1
            
            # Count by justification
            if justification not in report['by_justification']:
                report['by_justification'][justification] = 0
            report['by_justification'][justification] += 1
        
        # Calculate analysis coverage (how many CVEs have been analyzed)
        analyzed_count = (report['resolved'] + report['resolved_with_pedigree'] + 
                         report['exploitable'] + report['false_positive'] + 
                         report['not_affected'])
        if report['total'] > 0:
            report['analysis_coverage'] = (analyzed_count / report['total']) * 100
        
        # Generate summary text
        report['summary'] = {
            'completion_rate': report['analysis_coverage'],
            'by_state': {
                'resolved': report['resolved'],
                'resolved_with_pedigree': report['resolved_with_pedigree'],
                'exploitable': report['exploitable'],
                'in_triage': report['in_triage'],
                'false_positive': report['false_positive'],
                'not_affected': report['not_affected']
            },
            'risk_level': self._calculate_risk_level(report),
            'recommendations': self._generate_recommendations(report)
        }
        
        return report
    
    def _calculate_risk_level(self, report: Dict) -> str:
        """Calculate overall risk level based on analysis results."""
        total = report['total']
        exploitable = report['exploitable']
        
        if total == 0:
            return 'unknown'
        
        exploitable_ratio = exploitable / total
        
        if exploitable_ratio >= 0.3:
            return 'high'
        elif exploitable_ratio >= 0.1:
            return 'medium'
        elif exploitable_ratio > 0:
            return 'low'
        else:
            return 'minimal'
    
    def _generate_recommendations(self, report: Dict) -> List[str]:
        """Generate recommendations based on analysis results."""
        recommendations = []
        
        total = report['total']
        exploitable = report['exploitable']
        in_triage = report['in_triage']
        
        if exploitable > 0:
            recommendations.append(f"Review {exploitable} exploitable vulnerabilities immediately")
        
        if in_triage > total * 0.2:  # More than 20% in triage
            recommendations.append("Consider enabling patch checking for better analysis coverage")
        
        if report['analysis_coverage'] < 80:
            recommendations.append("Improve analysis coverage by providing kernel source and configuration")
        
        # Severity-based recommendations
        severity_breakdown = report.get('by_severity', {})
        critical_high = severity_breakdown.get('CRITICAL', 0) + severity_breakdown.get('HIGH', 0)
        
        if critical_high > 0:
            recommendations.append(f"Prioritize {critical_high} CRITICAL/HIGH severity vulnerabilities")
        
        if not recommendations:
            recommendations.append("Good security posture - continue monitoring for new vulnerabilities")
        
        return recommendations
    
    @timed_method
    def print_summary_report(self, report: Dict) -> None:
        """
        Print a formatted summary report to console.
        
        Args:
            report: Report dictionary from generate_summary_report
        """
        total = report.get('total', 0)
        resolved = report.get('resolved', 0)
        resolved_with_pedigree = report.get('resolved_with_pedigree', 0)
        exploitable = report.get('exploitable', 0)
        in_triage = report.get('in_triage', 0)
        false_positive = report.get('false_positive', 0)
        not_affected = report.get('not_affected', 0)
        
        print(f"\n📊 VULNERABILITY ANALYSIS SUMMARY")
        print(f"{'='*50}")
        print(f"📋 Total vulnerabilities: {total}")
        print(f"├─ ✅ Not affected: {not_affected}")
        print(f"├─ 🔧 Resolved: {resolved}")
        print(f"├─ 🔧📋 Resolved with pedigree: {resolved_with_pedigree}")
        print(f"├─ ⚠️  Exploitable: {exploitable}")
        print(f"├─ ❌ False positive: {false_positive}")
        print(f"└─ 🔍 In triage: {in_triage}")
        
        if total > 0:
            completion_rate = report.get('analysis_coverage', 0)
            print(f"\n📈 Analysis coverage: {completion_rate:.1f}%")
        
        # Show risk level
        risk_level = report.get('summary', {}).get('risk_level', 'unknown')
        risk_emoji = {'high': '🔴', 'medium': '🟡', 'low': '🟢', 'minimal': '⚪', 'unknown': '⚫'}
        print(f"🎯 Risk level: {risk_emoji.get(risk_level, '⚫')} {risk_level.upper()}")
        
        # Show severity breakdown if available
        severity_breakdown = report.get('by_severity', {})
        if severity_breakdown:
            print(f"\n📊 Severity breakdown:")
            for severity, count in sorted(severity_breakdown.items()):
                if count > 0:
                    print(f"  {severity}: {count}")
        
        # Show exploitable vulnerabilities if any
        if exploitable > 0:
            print(f"\n⚠️  EXPLOITABLE VULNERABILITIES:")
            vulnerabilities = report.get('vulnerabilities', {})
            exploitable_list = [
                cve_id for cve_id, details in vulnerabilities.items() 
                if details.get('state') == VulnerabilityState.EXPLOITABLE.value
            ]
            for cve_id in sorted(exploitable_list[:10]):  # Show first 10
                print(f"  • {cve_id}")
            
            if len(exploitable_list) > 10:
                print(f"  ... and {len(exploitable_list) - 10} more")
        
        # Show recommendations
        recommendations = report.get('summary', {}).get('recommendations', [])
        if recommendations:
            print(f"\n💡 RECOMMENDATIONS:")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        print()  # Empty line at end
    
    @timed_method
    def generate_detailed_report(self, vex_data: Dict, include_configs: bool = False) -> Dict[str, Any]:
        """
        Generate a detailed analysis report with individual CVE details.
        
        Args:
            vex_data: VEX document data
            include_configs: Include configuration analysis details
            
        Returns:
            Dictionary with detailed report data
        """
        summary = self.generate_summary_report(vex_data)
        vulnerabilities = vex_data.get('vulnerabilities', [])
        
        detailed_report = {
            'summary': summary,
            'detailed_analysis': [],
            'configuration_analysis': {} if include_configs else None,
            'metadata': {
                'generated_at': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                'tool_version': getattr(self, 'version', 'unknown'),
                'analysis_options': {
                    'check_patches': self.check_patches,
                    'analyze_all_cves': self.analyze_all_cves,
                    'architecture': self.arch
                }
            }
        }
        
        # Generate detailed analysis for each vulnerability
        for vuln in vulnerabilities:
            cve_id = vuln.get('id', 'unknown')
            analysis = vuln.get('analysis', {})
            
            detailed_vuln = {
                'cve_id': cve_id,
                'description': vuln.get('description', ''),
                'severity': vuln.get('severity', 'unknown'),
                'analysis': {
                    'state': analysis.get('state', ''),  # Use empty string as default, not 'in_triage'
                    'justification': analysis.get('justification', ''),
                    'detail': analysis.get('detail', ''),
                    'timestamp': analysis.get('timestamp', '')
                }
            }
            
            # Add response information if available
            if 'response' in analysis:
                detailed_vuln['analysis']['response'] = analysis['response']
            
            # Add source information if available
            if 'sources' in vuln:
                detailed_vuln['sources'] = vuln['sources']
            
            detailed_report['detailed_analysis'].append(detailed_vuln)
        
        return detailed_report
    
    @timed_method
    def generate_performance_report(self) -> Dict[str, Any]:
        """
        Generate a performance analysis report.
        
        Returns:
            Dictionary with performance metrics
        """
        return {
            'timing_summary': self.perf_tracker.timings,
            'cache_statistics': {
                'tracker_stats': self.perf_tracker.cache_stats,
                'local_hits': getattr(self, '_cache_hits', {}),
                'local_misses': getattr(self, '_cache_misses', {}),
                'hit_rate': self._calculate_cache_hit_rates()
            },
            'processed_items': {
                'cves': len(getattr(self, '_processed_cves', set())),
                'files_analyzed': len(getattr(self, '_file_content_cache', {}))
            },
            'recommendations': self._generate_performance_recommendations()
        }
    
    def _calculate_cache_hit_rates(self) -> Dict[str, float]:
        """Calculate cache hit rates for different cache types."""
        hit_rates = {}
        cache_hits = getattr(self, '_cache_hits', {})
        cache_misses = getattr(self, '_cache_misses', {})
        
        for cache_type in cache_hits:
            hits = cache_hits.get(cache_type, 0)
            misses = cache_misses.get(cache_type, 0)
            total = hits + misses
            
            if total > 0:
                hit_rates[cache_type] = (hits / total) * 100
            else:
                hit_rates[cache_type] = 0.0
        
        return hit_rates
    
    def _generate_performance_recommendations(self) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        hit_rates = self._calculate_cache_hit_rates()
        
        for cache_type, hit_rate in hit_rates.items():
            if hit_rate < 50:
                recommendations.append(f"Consider optimizing {cache_type} cache usage (hit rate: {hit_rate:.1f}%)")
        
        # Check timing data for slow operations
        timings = self.perf_tracker.timings
        slow_operations = []
        
        for operation, timing_data in timings.items():
            if isinstance(timing_data, dict) and 'duration' in timing_data:
                if timing_data['duration'] > 5.0:  # Operations taking more than 5 seconds
                    slow_operations.append((operation, timing_data['duration']))
        
        if slow_operations:
            recommendations.append("Consider optimizing slow operations: " + 
                                 ", ".join([f"{op} ({time:.1f}s)" for op, time in slow_operations]))
        
        if not recommendations:
            recommendations.append("Performance looks good!")
        
        return recommendations
    
    @timed_method
    def export_report(self, report: Dict, output_file: str, format: str = 'json') -> bool:
        """
        Export report to file in specified format.
        
        Args:
            report: Report dictionary to export
            output_file: Output file path
            format: Export format ('json', 'yaml', 'txt')
            
        Returns:
            True if export successful
        """
        try:
            if format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(report, f, indent=2, sort_keys=True)
            
            elif format.lower() == 'yaml':
                try:
                    import yaml
                    with open(output_file, 'w') as f:
                        yaml.safe_dump(report, f, default_flow_style=False, sort_keys=True)
                except ImportError:
                    if self.verbose:
                        print("YAML export requires PyYAML package")
                    return False
            
            elif format.lower() == 'txt':
                with open(output_file, 'w') as f:
                    f.write(self._format_report_as_text(report))
            
            else:
                if self.verbose:
                    print(f"Unsupported export format: {format}")
                return False
            
            if self.verbose:
                print(f"Report exported to {output_file}")
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"Error exporting report: {e}")
            return False
    
    def _format_report_as_text(self, report: Dict) -> str:
        """Format report as human-readable text."""
        lines = []
        lines.append("VEX KERNEL CHECKER REPORT")
        lines.append("=" * 50)
        lines.append(f"Generated: {report.get('timestamp', 'unknown')}")
        lines.append("")
        
        # Summary section
        if 'summary' in report:
            summary = report['summary']
            lines.append("SUMMARY")
            lines.append("-" * 20)
            lines.append(f"Total vulnerabilities: {report.get('total', 0)}")
            
            by_state = summary.get('by_state', {})
            for state, count in by_state.items():
                if count > 0:
                    lines.append(f"  {state.replace('_', ' ').title()}: {count}")
            
            lines.append(f"Risk level: {summary.get('risk_level', 'unknown').upper()}")
            lines.append(f"Analysis coverage: {summary.get('completion_rate', 0):.1f}%")
            lines.append("")
        
        # Recommendations section
        if 'summary' in report and 'recommendations' in report['summary']:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 20)
            for i, rec in enumerate(report['summary']['recommendations'], 1):
                lines.append(f"{i}. {rec}")
            lines.append("")
        
        # Detailed vulnerabilities section
        if 'vulnerabilities' in report:
            lines.append("VULNERABILITY DETAILS")
            lines.append("-" * 30)
            
            for cve_id, details in sorted(report['vulnerabilities'].items()):
                lines.append(f"CVE: {cve_id}")
                lines.append(f"  State: {details.get('state', 'unknown')}")
                lines.append(f"  Justification: {details.get('justification', '')}")
                lines.append(f"  Severity: {details.get('severity', 'unknown')}")
                if details.get('detail'):
                    lines.append(f"  Detail: {details['detail']}")
                lines.append("")
        
        return "\n".join(lines)
