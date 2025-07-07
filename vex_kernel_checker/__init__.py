"""
VEX Kernel Checker Package

A modular vulnerability analysis tool for Linux kernel configurations.
"""

from .base import VexKernelCheckerBase
from .cve_manager import CVEDataManager
from .patch_manager import PatchManager
from .config_analyzer import ConfigurationAnalyzer
from .vulnerability_analyzer import VulnerabilityAnalyzer
from .architecture_manager import ArchitectureManager
from .report_generator import ReportGenerator
from .main_checker import VexKernelChecker
from .common import *

__version__ = "2.1.0"
__author__ = "Karsten S. Opdal"
__license__ = "MIT"

__all__ = [
    "VexKernelCheckerBase",
    "CVEDataManager", 
    "PatchManager",
    "ConfigurationAnalyzer",
    "VulnerabilityAnalyzer",
    "ArchitectureManager",
    "ReportGenerator",
    "VexKernelChecker",
    "VulnerabilityState",
    "Justification",
    "Response",
    "VulnerabilityAnalysis",
    "CVEInfo",
    "PerformanceTracker"
]
