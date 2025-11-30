#!/usr/bin/env python3
"""
Performance benchmarking script for VEX Kernel Checker.

This script runs performance tests using the main CLI script to measure
execution times for real-world operations.
"""

import sys
import os
import time
import json
import argparse
import statistics
import subprocess
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


class BenchmarkRunner:
    """Main benchmark runner class."""

    def __init__(self, quiet=False, iterations=3):
        self.quiet = quiet
        self.iterations = iterations
        self.results = {}
        self.test_data_dir = project_root / "examples"
        self.main_script = project_root / "vex-kernel-checker.py"

    def log(self, message):
        """Log message if not in quiet mode."""
        if not self.quiet:
            print(message)

    def run_timed_operation(self, name, operation, *args, **kwargs):
        """Run an operation multiple times and collect timing statistics."""
        self.log(f"\n🔬 Benchmarking: {name}")
        times = []

        for i in range(self.iterations):
            self.log(f"  Iteration {i+1}/{self.iterations}")
            start_time = time.time()
            try:
                result = operation(*args, **kwargs)
                end_time = time.time()
                duration = end_time - start_time
                times.append(duration)
                self.log(f"    Duration: {duration:.3f}s")
            except Exception as e:
                self.log(f"    ❌ Error: {e}")
                return None

        if times:
            stats = {
                "operation": name,
                "iterations": len(times),
                "mean": statistics.mean(times),
                "median": statistics.median(times),
                "min": min(times),
                "max": max(times),
                "stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
                "times": times,
            }

            self.results[name] = stats
            self.log(
                f"  📊 Results: mean={stats['mean']:.3f}s, "
                f"median={stats['median']:.3f}s, "
                f"min={stats['min']:.3f}s, max={stats['max']:.3f}s"
            )
            return stats

        return None

    def run_cli_command(self, args):
        """Run the main CLI script with given arguments."""
        cmd = [sys.executable, str(self.main_script)] + args
        result = subprocess.run(cmd, capture_output=True, text=True, cwd=project_root)
        return result.returncode == 0

    def benchmark_vex_analysis(self):
        """Benchmark VEX file analysis using CLI."""
        self.log("\n🔍 Benchmarking VEX Analysis")

        # Test with different VEX file sizes
        test_files = [
            "test_small_vex.json",
            "test_real_cve.json",
            "test_mixed_vex.json",
        ]

        kernel_source = self.test_data_dir / "test_kernel_source"
        if not kernel_source.exists():
            self.log("  ⚠️  Skipping VEX analysis (test kernel source not found)")
            return

        for test_file in test_files:
            vex_path = self.test_data_dir / test_file
            if not vex_path.exists():
                self.log(f"  ⚠️  Skipping {test_file} (not found)")
                continue

            # Create a test config file if it doesn't exist
            config_files = [
                kernel_source / ".config",
                self.test_data_dir / "test_demo.config",
                kernel_source / "sample.config",
            ]

            config_path = None
            for config_file in config_files:
                if config_file.exists():
                    config_path = config_file
                    break

            if not config_path:
                self.log(f"  ⚠️  Skipping {test_file} (no config file)")
                continue

            # Benchmark full analysis
            self.run_timed_operation(
                f"Full VEX Analysis ({test_file})",
                self.run_cli_command,
                [
                    "--vex-file",
                    str(vex_path),
                    "--kernel-config",
                    str(config_path),
                    "--kernel-source",
                    str(kernel_source),
                    "--config-only",
                    "--quiet",
                ],
            )

    def benchmark_config_analysis(self):
        """Benchmark configuration analysis using CLI."""
        self.log("\n⚙️  Benchmarking Config Analysis")

        kernel_source = self.test_data_dir / "test_kernel_source"
        if not kernel_source.exists():
            self.log("  ⚠️  Skipping config analysis (test kernel source not found)")
            return

        # Find a valid config file
        config_files = [
            kernel_source / ".config",
            self.test_data_dir / "test_demo.config",
            kernel_source / "sample.config",
            self.test_data_dir / "test_kernel_source" / ".config",
        ]

        config_path = None
        for config_file in config_files:
            if config_file.exists():
                config_path = config_file
                break

        if not config_path:
            self.log("  ⚠️  Skipping config analysis (no config file found)")
            return

        vex_path = self.test_data_dir / "test_small_vex.json"
        if not vex_path.exists():
            self.log("  ⚠️  Skipping config analysis (no VEX file found)")
            return

        # Benchmark config-only mode
        self.run_timed_operation(
            "Config-Only Analysis",
            self.run_cli_command,
            [
                "--vex-file",
                str(vex_path),
                "--kernel-config",
                str(config_path),
                "--kernel-source",
                str(kernel_source),
                "--config-only",
                "--quiet",
            ],
        )

    def benchmark_filesystem_analysis(self):
        """Benchmark filesystem analysis using CLI."""
        self.log("\n�️  Benchmarking Filesystem Analysis")

        kernel_source = self.test_data_dir / "test_kernel_source"
        if not kernel_source.exists():
            self.log("  ⚠️  Skipping filesystem analysis (test kernel source not found)")
            return

        vex_path = self.test_data_dir / "test_small_vex.json"
        if not vex_path.exists():
            self.log("  ⚠️  Skipping filesystem analysis (no VEX file found)")
            return

        config_path = kernel_source / ".config"
        if not config_path.exists():
            config_path = self.test_data_dir / "test_demo.config"
            if not config_path.exists():
                config_path = kernel_source / "sample.config"
                if not config_path.exists():
                    self.log("  ⚠️  Skipping filesystem analysis (no config file)")
                    return

        # Benchmark filesystem mode (without config-only)
        self.run_timed_operation(
            "Filesystem Analysis",
            self.run_cli_command,
            [
                "--vex-file",
                str(vex_path),
                "--kernel-config",
                str(config_path),
                "--kernel-source",
                str(kernel_source),
                "--quiet",
            ],
        )

    def benchmark_help_and_validation(self):
        """Benchmark help and basic validation operations."""
        self.log("\n❓ Benchmarking Help and Validation")

        # Benchmark help display
        self.run_timed_operation("Help Display", self.run_cli_command, ["--help"])

        # Benchmark version display
        self.run_timed_operation("Version Display", self.run_cli_command, ["--version"])

    def run_full_benchmark(self):
        """Run all benchmark tests."""
        self.log("🚀 Starting VEX Kernel Checker Performance Benchmarks")
        self.log(f"   Iterations per test: {self.iterations}")
        self.log(f"   Quiet mode: {self.quiet}")

        start_time = time.time()

        # Run all benchmark categories
        self.benchmark_vex_analysis()
        self.benchmark_config_analysis()
        self.benchmark_filesystem_analysis()
        self.benchmark_help_and_validation()

        end_time = time.time()
        total_duration = end_time - start_time

        self.log(f"\n✅ Benchmarks completed in {total_duration:.2f} seconds")

        return self.results

    def save_results(self, output_file="benchmark_results.json"):
        """Save benchmark results to JSON file."""
        output_path = project_root / output_file

        # Add metadata
        results_with_metadata = {
            "benchmark_metadata": {
                "timestamp": time.time(),
                "iterations": self.iterations,
                "python_version": sys.version,
                "platform": sys.platform,
            },
            "results": self.results,
        }

        try:
            with open(output_path, "w") as f:
                json.dump(results_with_metadata, f, indent=2)
            self.log(f"\n💾 Results saved to {output_path}")
        except Exception as e:
            self.log(f"\n❌ Error saving results: {e}")

    def print_summary(self):
        """Print a summary of benchmark results."""
        if not self.results:
            self.log("No benchmark results to summarize.")
            return

        self.log("\n📈 Benchmark Summary")
        self.log("=" * 50)

        # Sort by mean time
        sorted_results = sorted(self.results.items(), key=lambda x: x[1]["mean"])

        for name, stats in sorted_results:
            self.log(f"{name:30} | {stats['mean']:6.3f}s ± {stats['stdev']:6.3f}s")

        # Overall statistics
        all_times = [stats["mean"] for stats in self.results.values()]
        if all_times:
            self.log("\n📊 Overall Statistics")
            self.log(f"Total operations benchmarked: {len(all_times)}")
            self.log(f"Fastest operation: {min(all_times):.3f}s")
            self.log(f"Slowest operation: {max(all_times):.3f}s")
            self.log(f"Average operation time: {statistics.mean(all_times):.3f}s")


def main():
    """Main entry point for benchmark script."""
    parser = argparse.ArgumentParser(
        description="Run performance benchmarks for VEX Kernel Checker"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Run in quiet mode with minimal output"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=3,
        help="Number of iterations per benchmark (default: 3)",
    )
    parser.add_argument(
        "--output",
        default="benchmark_results.json",
        help="Output file for benchmark results (default: benchmark_results.json)",
    )
    parser.add_argument("--no-save", action="store_true", help="Don't save results to file")

    args = parser.parse_args()

    # Run benchmarks
    runner = BenchmarkRunner(quiet=args.quiet, iterations=args.iterations)
    results = runner.run_full_benchmark()

    # Print summary
    runner.print_summary()

    # Save results
    if not args.no_save:
        runner.save_results(args.output)

    # Return exit code based on whether we got results
    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
