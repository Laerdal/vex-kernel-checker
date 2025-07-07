"""
Common data structures and utilities for VEX Kernel Checker.
"""

import functools
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class VulnerabilityState(Enum):
    """Enumeration of possible vulnerability states according to CycloneDX v1.6."""

    RESOLVED = "resolved"
    RESOLVED_WITH_PEDIGREE = "resolved_with_pedigree"
    EXPLOITABLE = "exploitable"
    IN_TRIAGE = "in_triage"
    FALSE_POSITIVE = "false_positive"
    NOT_AFFECTED = "not_affected"


class Justification(Enum):
    """Enumeration of justification reasons for vulnerability state according to CycloneDX v1.6."""

    CODE_NOT_PRESENT = "code_not_present"
    CODE_NOT_REACHABLE = "code_not_reachable"
    REQUIRES_CONFIGURATION = "requires_configuration"
    REQUIRES_DEPENDENCY = "requires_dependency"
    REQUIRES_ENVIRONMENT = "requires_environment"
    PROTECTED_BY_COMPILER = "protected_by_compiler"
    PROTECTED_AT_RUNTIME = "protected_at_runtime"
    PROTECTED_AT_PERIMETER = "protected_at_perimeter"
    PROTECTED_BY_MITIGATING_CONTROL = "protected_by_mitigating_control"


class Response(Enum):
    """Enumeration of response actions for vulnerabilities."""

    CAN_NOT_FIX = "can_not_fix"
    WILL_NOT_FIX = "will_not_fix"
    UPDATE = "update"
    ROLLBACK = "rollback"
    WORKAROUND_AVAILABLE = "workaround_available"


@dataclass
class VulnerabilityAnalysis:
    """Data class representing the analysis of a vulnerability."""

    state: VulnerabilityState
    justification: Optional[Justification] = None
    response: Optional[Response] = None
    detail: Optional[str] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {"state": self.state.value}
        if self.justification:
            result["justification"] = self.justification.value
        if self.response:
            result["response"] = self.response.value
        if self.detail:
            result["detail"] = self.detail
        if self.timestamp:
            result["timestamp"] = self.timestamp
        return result


@dataclass
class CVEInfo:
    """Data class for CVE information."""

    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    description: Optional[str] = None
    patch_urls: Optional[List[str]] = None
    published_date: Optional[str] = None
    modified_date: Optional[str] = None


class PerformanceTracker:
    """Advanced performance tracking for optimization and debugging."""

    def __init__(self):
        """Initialize the PerformanceTracker with empty timings and cache stats."""
        self.timings = {}
        self.cache_stats = {}

    def start_timer(self, name: str):
        """Start timing an operation."""
        self.timings[name] = {"start": time.time()}

    def end_timer(self, name: str):
        """End timing an operation."""
        if name in self.timings:
            self.timings[name]["duration"] = time.time() - self.timings[name]["start"]

    def record_cache_hit(self, cache_name: str):
        """Record a cache hit."""
        if cache_name not in self.cache_stats:
            self.cache_stats[cache_name] = {"hits": 0, "misses": 0}
        self.cache_stats[cache_name]["hits"] += 1

    def record_cache_miss(self, cache_name: str):
        """Record a cache miss."""
        if cache_name not in self.cache_stats:
            self.cache_stats[cache_name] = {"hits": 0, "misses": 0}
        self.cache_stats[cache_name]["misses"] += 1

    def record_timing(self, operation_name: str, duration: float):
        """Record timing for an operation directly."""
        self.timings[operation_name] = duration

    def get_summary(self) -> Dict[str, Any]:
        """Get performance summary as dictionary."""
        # Calculate total operations and time
        total_operations = len(
            [
                name
                for name, data in self.timings.items()
                if isinstance(data, (int, float)) or "duration" in data
            ]
        )

        total_time = 0
        for name, data in self.timings.items():
            if isinstance(data, (int, float)):
                total_time += data
            elif isinstance(data, dict) and "duration" in data:
                total_time += data["duration"]

        # Process cache stats
        cache_summary = {}
        for cache_name, stats in self.cache_stats.items():
            hits = stats["hits"]
            misses = stats["misses"]
            total = hits + misses
            hit_rate = (hits / total * 100) if total > 0 else 0

            cache_summary[cache_name] = {
                "hits": hits,
                "misses": misses,
                "total": total,
                "hit_rate": hit_rate,
            }

        return {
            "total_operations": total_operations,
            "total_time": total_time,
            "cache_summary": cache_summary,
            "detailed_timings": self.timings.copy(),
        }

    def print_summary(self):
        """Print performance summary."""
        print("\n" + "=" * 60)
        print("🚀 PERFORMANCE SUMMARY")
        print("=" * 60)

        if self.timings:
            print("\n⏱️  TIMING RESULTS:")
            for name, data in sorted(self.timings.items()):
                if "duration" in data:
                    print(f"  {name}: {data['duration']:.3f}s")

        if self.cache_stats:
            print("\n💾 CACHE PERFORMANCE:")
            total_hits = total_requests = 0
            for cache_name, stats in sorted(self.cache_stats.items()):
                hits = stats["hits"]
                misses = stats["misses"]
                total = hits + misses
                hit_rate = (hits / total * 100) if total > 0 else 0

                total_hits += hits
                total_requests += total

                print(f"  {cache_name}:")
                print(f"    Hits: {hits}, Misses: {misses}, Hit Rate: {hit_rate:.1f}%")

            if total_requests > 0:
                overall_hit_rate = total_hits / total_requests * 100
                print(f"\n  Overall Cache Hit Rate: {overall_hit_rate:.1f}%")

        print("=" * 60)


# Global settings for performance monitoring
ENABLE_TIMING_OUTPUT = False  # Set to True to show detailed method timing


def timed_method(func):
    """Decorator to time method execution for performance monitoring."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = end_time - start_time

        # Only print timing if globally enabled or if instance has detailed_timing enabled
        show_timing = ENABLE_TIMING_OUTPUT

        # Check if this is a method call and the instance has detailed timing enabled
        if not show_timing and args and hasattr(args[0], "__class__"):
            instance = args[0]
            if hasattr(instance, "detailed_timing") and instance.detailed_timing:
                show_timing = True

        if show_timing:
            # Get class name if this is a method
            class_name = ""
            if args and hasattr(args[0], "__class__"):
                class_name = f"{args[0].__class__.__name__}."

            print(f"⏱️  {class_name}{func.__name__}: {duration:.3f}s")

        return result

    return wrapper


# Global interrupt flag for graceful shutdown
_interrupt_requested = threading.Event()


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    print(
        f"\n🛑 Interrupt signal received (signal {signum}). Gracefully shutting down..."
    )
    _interrupt_requested.set()


def check_interrupt():
    """Check if an interrupt has been requested."""
    if _interrupt_requested.is_set():
        raise KeyboardInterrupt("Analysis interrupted by user request")


# Global performance tracker
perf_tracker = PerformanceTracker()
