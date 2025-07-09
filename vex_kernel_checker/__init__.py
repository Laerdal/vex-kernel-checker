"""
VEX Kernel Checker Package.

A modular vulnerability analysis tool for Linux kernel configurations.
"""

from .architecture_manager import ArchitectureManager
from .base import VexKernelCheckerBase
from .common import (
    CVEInfo,
    Justification,
    PerformanceTracker,
    Response,
    VulnerabilityAnalysis,
    VulnerabilityState,
)
from .config_analyzer import ConfigurationAnalyzer
from .cve_manager import CVEDataManager
from .logging_utils import configure_logging, get_logger, is_verbose
from .main_checker import VexKernelChecker
from .patch_manager import PatchManager
from .report_generator import ReportGenerator
from .vulnerability_analyzer import VulnerabilityAnalyzer

__version__ = '2.1.0'
__author__ = 'Karsten S. Opdal'
__license__ = 'MIT'

__all__ = [
    'VexKernelCheckerBase',
    'CVEDataManager',
    'PatchManager',
    'ConfigurationAnalyzer',
    'VulnerabilityAnalyzer',
    'ArchitectureManager',
    'ReportGenerator',
    'VexKernelChecker',
    'VulnerabilityState',
    'Justification',
    'Response',
    'VulnerabilityAnalysis',
    'CVEInfo',
    'PerformanceTracker',
    'configure_logging',
    'get_logger',
    'is_verbose',
]
