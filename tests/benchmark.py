#!/usr/bin/env python3
"""
Performance benchmarking suite for VEX Kernel Checker.

This script provides comprehensive performance testing and benchmarking
capabilities to help optimize the VEX Kernel Checker tool.
"""

import os
import sys
import time
import json
import tempfile
import shutil
import statistics
import traceback
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import psutil
import tracemalloc

# Add the parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("vex_kernel_checker", 
                                                 Path(__file__).parent.parent / "../vex-kernel-checker.py")
    if spec is None or spec.loader is None:
        raise ImportError("Could not create module spec for vex_kernel_checker")
    vkc_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vkc_module)
    VexKernelChecker = vkc_module.VexKernelChecker
except Exception as e:
    print(f"Failed to import VEX Kernel Checker: {e}")
    sys.exit(1)

class PerformanceBenchmark:
    """Performance benchmarking suite for VEX Kernel Checker."""
    
    def __init__(self, verbose=True):
        self.verbose = verbose
        self.results = {}
        self.temp_dir = None
        
    def setup_test_environment(self):
        """Set up a comprehensive test environment."""
        self.temp_dir = tempfile.mkdtemp(prefix="vkc_benchmark_")
        
        if self.verbose:
            print(f"Setting up test environment in: {self.temp_dir}")
        
        # Create realistic kernel source structure
        kernel_source = Path(self.temp_dir) / "kernel_source"
        self.create_realistic_kernel_structure(kernel_source)
        
        # Create test configurations
        self.create_test_configs()
        
        # Create test VEX data with various CVE types
        self.create_comprehensive_vex_data()
        
        return kernel_source
    
    def create_realistic_kernel_structure(self, kernel_source):
        """Create a realistic kernel source structure for testing."""
        # Major subsystems
        subsystems = [
            "drivers/net/ethernet",
            "drivers/net/wireless", 
            "drivers/usb/core",
            "drivers/usb/storage",
            "drivers/pci",
            "drivers/scsi",
            "drivers/block",
            "drivers/char",
            "fs/ext4",
            "fs/btrfs",
            "net/core",
            "net/ipv4",
            "net/ipv6",
            "sound/core",
            "sound/pci",
            "crypto",
            "security",
            "arch/x86/kernel",
            "arch/arm/mach-omap2",
            "kernel",
            "mm"
        ]
        
        for subsys in subsystems:
            subsys_path = kernel_source / subsys
            subsys_path.mkdir(parents=True, exist_ok=True)
            
            # Create multiple source files per subsystem
            for i in range(3):
                source_file = subsys_path / f"test_file_{i}.c"
                makefile = subsys_path / "Makefile"
                
                # Create source file with realistic CONFIG patterns
                self.create_realistic_source_file(source_file, subsys)
                
                # Create Makefile with realistic patterns
                if not makefile.exists():
                    self.create_realistic_makefile(makefile, subsys)
    
    def create_realistic_source_file(self, source_file, subsystem):
        """Create a realistic source file with CONFIG patterns."""
        config_patterns = {
            "drivers/net": ["CONFIG_NET", "CONFIG_NETDEVICES", "CONFIG_ETHERNET"],
            "drivers/usb": ["CONFIG_USB", "CONFIG_USB_SUPPORT"],
            "drivers/pci": ["CONFIG_PCI"],
            "fs": ["CONFIG_FILESYSTEMS", "CONFIG_EXT4_FS", "CONFIG_BTRFS_FS"],
            "net": ["CONFIG_NET", "CONFIG_INET"],
            "sound": ["CONFIG_SOUND", "CONFIG_SND"],
            "crypto": ["CONFIG_CRYPTO"],
            "security": ["CONFIG_SECURITY"]
        }
        
        # Find matching patterns
        configs = []
        for pattern, config_list in config_patterns.items():
            if pattern in subsystem:
                configs.extend(config_list)
        
        if not configs:
            configs = ["CONFIG_GENERIC_FEATURE"]
        
        source_content = f"""/*
 * Test source file for {subsystem}
 */
#include <linux/module.h>
#include <linux/kernel.h>

"""
        
        # Add various CONFIG patterns
        for i, config in enumerate(configs[:3]):  # Limit to 3 configs per file
            source_content += f"""
#ifdef {config}
static int feature_{i}_enabled = 1;
#endif

#if defined({config})
static void feature_{i}_init(void) {{
    // Feature {i} initialization
}}
#endif

#if IS_ENABLED({config})
static struct feature_{i}_data {{
    int value;
}} feature_{i}_data;
#endif

"""
        
        source_content += """
static int __init test_module_init(void) {
    return 0;
}

static void __exit test_module_exit(void) {
}

module_init(test_module_init);
module_exit(test_module_exit);
MODULE_LICENSE("GPL");
"""
        
        with open(source_file, 'w') as f:
            f.write(source_content)
    
    def create_realistic_makefile(self, makefile, subsystem):
        """Create a realistic Makefile."""
        config_patterns = {
            "drivers/net": "CONFIG_NET",
            "drivers/usb": "CONFIG_USB", 
            "drivers/pci": "CONFIG_PCI",
            "fs": "CONFIG_FILESYSTEMS",
            "net": "CONFIG_NET",
            "sound": "CONFIG_SOUND",
            "crypto": "CONFIG_CRYPTO",
            "security": "CONFIG_SECURITY"
        }
        
        main_config = "CONFIG_GENERIC_FEATURE"
        for pattern, config in config_patterns.items():
            if pattern in subsystem:
                main_config = config
                break
        
        makefile_content = f"""#
# Makefile for {subsystem}
#

obj-$({main_config}) += test_file_0.o
obj-$({main_config}) += test_file_1.o
obj-$({main_config}) += test_file_2.o

test_module-objs := test_file_0.o test_file_1.o test_file_2.o

ifdef {main_config}
    EXTRA_CFLAGS += -DFEATURE_ENABLED
endif

ifeq ($({main_config}),y)
    obj-y += additional_feature.o
endif
"""
        
        with open(makefile, 'w') as f:
            f.write(makefile_content)
    
    def create_test_configs(self):
        """Create test kernel configuration files."""
        if self.temp_dir is None:
            raise RuntimeError("temp_dir not initialized. Call setup_test_environment() first.")
        
        configs = {
            "minimal.config": [
                "CONFIG_NET=y",
                "CONFIG_BLOCK=y", 
                "CONFIG_FILESYSTEMS=y"
            ],
            "full.config": [
                "CONFIG_NET=y",
                "CONFIG_NETDEVICES=y",
                "CONFIG_ETHERNET=y",
                "CONFIG_USB=y",
                "CONFIG_USB_SUPPORT=y",
                "CONFIG_PCI=y",
                "CONFIG_SCSI=y",
                "CONFIG_BLOCK=y",
                "CONFIG_FILESYSTEMS=y",
                "CONFIG_EXT4_FS=y",
                "CONFIG_BTRFS_FS=y",
                "CONFIG_SOUND=y",
                "CONFIG_SND=y",
                "CONFIG_CRYPTO=y",
                "CONFIG_SECURITY=y",
                "CONFIG_MODULES=y"
            ]
        }
        
        for config_name, config_lines in configs.items():
            config_path = Path(self.temp_dir) / config_name
            with open(config_path, 'w') as f:
                f.write("# Test kernel configuration\n")
                for line in config_lines:
                    f.write(f"{line}\n")
                f.write("# End of configuration\n")
    
    def create_comprehensive_vex_data(self):
        """Create comprehensive VEX test data."""
        if self.temp_dir is None:
            raise RuntimeError("temp_dir not initialized. Call setup_test_environment() first.")
        
        # Small dataset
        small_vex = {
            "vulnerabilities": [
                {
                    "id": f"CVE-2023-{1000 + i}",
                    "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                    "description": f"Test kernel vulnerability {i} in network subsystem"
                } for i in range(10)
            ]
        }
        
        # Medium dataset  
        medium_vex = {
            "vulnerabilities": [
                {
                    "id": f"CVE-2023-{2000 + i}",
                    "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                    "description": f"Test vulnerability {i} affecting various subsystems"
                } for i in range(50)
            ]
        }
        
        # Large dataset
        large_vex = {
            "vulnerabilities": [
                {
                    "id": f"CVE-2023-{3000 + i}",
                    "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                    "description": f"Large scale test vulnerability {i}"
                } for i in range(200)
            ]
        }
        
        datasets = {
            "small.vex": small_vex,
            "medium.vex": medium_vex,
            "large.vex": large_vex
        }
        
        for filename, data in datasets.items():
            vex_path = Path(self.temp_dir) / filename
            with open(vex_path, 'w') as f:
                json.dump(data, f, indent=2)
    
    def benchmark_method(self, method_name, method_func, *args, iterations=3, **kwargs):
        """Benchmark a specific method."""
        if self.verbose:
            print(f"\nBenchmarking: {method_name}")
        
        times = []
        memory_usage = []
        
        for i in range(iterations):
            # Start memory tracking
            tracemalloc.start()
            process = psutil.Process()
            start_memory = process.memory_info().rss
            
            # Time the execution
            start_time = time.perf_counter()
            result = method_func(*args, **kwargs)
            end_time = time.perf_counter()
            
            # Memory tracking
            end_memory = process.memory_info().rss
            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            
            duration = end_time - start_time
            memory_delta = end_memory - start_memory
            
            times.append(duration)
            memory_usage.append(memory_delta)
            
            if self.verbose:
                print(f"  Iteration {i+1}: {duration:.3f}s, Memory: {memory_delta/1024/1024:.1f}MB")
        
        stats = {
            'method': method_name,
            'iterations': iterations,
            'times': times,
            'avg_time': statistics.mean(times),
            'min_time': min(times),
            'max_time': max(times),
            'std_time': statistics.stdev(times) if len(times) > 1 else 0,
            'memory_usage': memory_usage,
            'avg_memory': statistics.mean(memory_usage),
            'peak_memory': max(memory_usage)
        }
        
        self.results[method_name] = stats
        
        if self.verbose:
            print(f"  Average: {stats['avg_time']:.3f}s ± {stats['std_time']:.3f}s")
            print(f"  Memory: {stats['avg_memory']/1024/1024:.1f}MB average")
        
        return stats
    
    def benchmark_configuration_analysis(self, kernel_source):
        """Benchmark configuration analysis methods."""
        if self.verbose:
            print("\n=== Configuration Analysis Benchmarks ===")
        
        checker = VexKernelChecker(verbose=False, disable_patch_checking=True)
        
        # Test files from different subsystems
        test_files = [
            kernel_source / "drivers/net/ethernet/test_file_0.c",
            kernel_source / "drivers/usb/core/test_file_0.c",
            kernel_source / "fs/ext4/test_file_0.c",
            kernel_source / "net/core/test_file_0.c"
        ]
        
        for test_file in test_files:
            if test_file.exists():
                # Benchmark Makefile analysis
                makefile_path = test_file.parent / "Makefile"
                self.benchmark_method(
                    f"makefile_analysis_{test_file.parent.name}",
                    checker.find_makefile_config_options,
                    str(test_file), str(makefile_path), str(kernel_source)
                )
                
                # Benchmark source file analysis
                self.benchmark_method(
                    f"source_analysis_{test_file.parent.name}",
                    checker._analyze_source_file_config_hints,
                    str(test_file)
                )
                
                # Benchmark path inference
                self.benchmark_method(
                    f"path_inference_{test_file.parent.name}",
                    checker._infer_config_from_path,
                    str(test_file), str(kernel_source)
                )
    
    def benchmark_vex_processing(self, kernel_source):
        """Benchmark VEX data processing."""
        if self.verbose:
            print("\n=== VEX Processing Benchmarks ===")
        
        checker = VexKernelChecker(verbose=False, disable_patch_checking=True)
        
        # Load kernel config
        config_path = Path(self.temp_dir) / "full.config"
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
        
        kernel_config = []
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        
        # Test different VEX dataset sizes
        vex_files = ["small.vex", "medium.vex", "large.vex"]
        
        for vex_file in vex_files:
            vex_path = Path(self.temp_dir) / vex_file
            with open(vex_path, 'r') as f:
                vex_data = json.load(f)
            
            dataset_size = len(vex_data['vulnerabilities'])
            
            self.benchmark_method(
                f"vex_processing_{dataset_size}_cves",
                checker.update_analysis_state,
                vex_data, kernel_config, str(kernel_source),
                iterations=1  # Reduce iterations for large datasets
            )
    
    def benchmark_caching_performance(self, kernel_source):
        """Benchmark caching performance improvements."""
        if self.verbose:
            print("\n=== Caching Performance Benchmarks ===")
        
        # Test with fresh checker (cold cache)
        checker_cold = VexKernelChecker(verbose=False, disable_patch_checking=True)
        
        test_file = kernel_source / "drivers/net/ethernet/test_file_0.c"
        makefile = test_file.parent / "Makefile"
        
        # Cold cache run
        self.benchmark_method(
            "makefile_analysis_cold_cache",
            checker_cold.find_makefile_config_options,
            str(test_file), str(makefile), str(kernel_source),
            iterations=1
        )
        
        # Warm cache run (same checker, same files)
        self.benchmark_method(
            "makefile_analysis_warm_cache",
            checker_cold.find_makefile_config_options,
            str(test_file), str(makefile), str(kernel_source),
            iterations=5
        )
        
        # Test cache hit ratio
        if hasattr(checker_cold, '_cache_hits') and hasattr(checker_cold, '_cache_misses'):
            for cache_type in checker_cold._cache_hits:
                hits = checker_cold._cache_hits[cache_type]
                misses = checker_cold._cache_misses[cache_type]
                total = hits + misses
                hit_ratio = (hits / total * 100) if total > 0 else 0
                
                print(f"  {cache_type} cache hit ratio: {hit_ratio:.1f}% ({hits}/{total})")
    
    def benchmark_parallel_processing(self, kernel_source):
        """Benchmark parallel processing capabilities."""
        if self.verbose:
            print("\n=== Parallel Processing Benchmarks ===")
        
        # Create multiple checkers for parallel testing
        def create_checker():
            return VexKernelChecker(verbose=False, disable_patch_checking=True)
        
        # Load test data
        config_path = Path(self.temp_dir) / "full.config"
        with open(config_path, 'r') as f:
            config_lines = f.readlines()
        
        kernel_config = []
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                config_name = line.split('=')[0]
                if line.endswith('=y') or line.endswith('=m'):
                    kernel_config.append(config_name)
        
        vex_path = Path(self.temp_dir) / "medium.vex"
        with open(vex_path, 'r') as f:
            vex_data = json.load(f)
        
        # Sequential processing
        checker_seq = create_checker()
        self.benchmark_method(
            "sequential_processing",
            checker_seq.update_analysis_state,
            vex_data, kernel_config, str(kernel_source),
            iterations=1
        )
        
        # Note: The actual parallel processing is handled internally by the checker
        # This benchmark measures the overall performance difference
    
    def generate_report(self):
        """Generate a comprehensive performance report."""
        if self.verbose:
            print("\n" + "="*60)
            print("PERFORMANCE BENCHMARK REPORT")
            print("="*60)
        
        # Sort results by average time
        sorted_results = sorted(self.results.items(), key=lambda x: x[1]['avg_time'])
        
        print(f"\n{'Method':<40} {'Avg Time':<12} {'Memory':<12} {'Iterations':<12}")
        print("-" * 80)
        
        for method_name, stats in sorted_results:
            avg_time = stats['avg_time']
            avg_memory = stats['avg_memory'] / 1024 / 1024  # Convert to MB
            iterations = stats['iterations']
            
            print(f"{method_name:<40} {avg_time:<12.3f}s {avg_memory:<12.1f}MB {iterations:<12}")
        
        # Performance insights
        print(f"\nPerformance Insights:")
        
        # Find fastest and slowest methods
        if sorted_results:
            fastest = sorted_results[0]
            slowest = sorted_results[-1]
            
            print(f"  Fastest: {fastest[0]} ({fastest[1]['avg_time']:.3f}s)")
            print(f"  Slowest: {slowest[0]} ({slowest[1]['avg_time']:.3f}s)")
            
            if slowest[1]['avg_time'] > 0:
                speedup = slowest[1]['avg_time'] / fastest[1]['avg_time']
                print(f"  Speed difference: {speedup:.1f}x")
        
        # Memory usage insights
        memory_results = [(name, stats['avg_memory']) for name, stats in self.results.items()]
        memory_results.sort(key=lambda x: x[1])
        
        if memory_results:
            print(f"  Lowest memory: {memory_results[0][0]} ({memory_results[0][1]/1024/1024:.1f}MB)")
            print(f"  Highest memory: {memory_results[-1][0]} ({memory_results[-1][1]/1024/1024:.1f}MB)")
        
        return self.results
    
    def cleanup(self):
        """Clean up test environment."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def run_full_benchmark(self):
        """Run the complete benchmark suite."""
        try:
            if self.verbose:
                print("Starting VEX Kernel Checker Performance Benchmark")
                print(f"Python version: {sys.version}")
                print(f"Platform: {os.uname().sysname} {os.uname().release}")
                
            kernel_source = self.setup_test_environment()
            
            # Run all benchmark categories
            self.benchmark_configuration_analysis(kernel_source)
            self.benchmark_caching_performance(kernel_source)
            self.benchmark_vex_processing(kernel_source)
            self.benchmark_parallel_processing(kernel_source)
            
            # Generate final report
            return self.generate_report()
            
        finally:
            self.cleanup()

def main():
    """Main entry point for benchmark script."""
    parser = argparse.ArgumentParser(description="VEX Kernel Checker Performance Benchmark")
    parser.add_argument('--quiet', '-q', action='store_true', help='Reduce output verbosity')
    parser.add_argument('--iterations', '-i', type=int, default=3, help='Number of iterations per benchmark')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    benchmark = PerformanceBenchmark(verbose=not args.quiet)
    
    try:
        results = benchmark.run_full_benchmark()
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\nResults saved to: {args.output}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        return 1
    except Exception as e:
        print(f"Benchmark failed: {e}")
        if not args.quiet:
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
