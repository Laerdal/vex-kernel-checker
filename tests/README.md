# VEX Kernel Checker Test Suite

This directory contains comprehensive testing tools for the VEX Kernel Checker project.

## Test Components

### 1. Unit and Integration Tests (`test_vex_kernel_checker.py`)

Comprehensive test suite covering:
- **Core Functionality**: VEX data processing, configuration analysis, CVE filtering
- **Makefile Analysis**: Configuration option extraction from Makefiles and Kbuild files
- **Source Code Analysis**: CONFIG pattern detection in C source files
- **Path-based Inference**: Configuration option inference from file paths
- **Error Handling**: Graceful handling of missing files and invalid data
- **Caching Performance**: Verification of caching mechanisms
- **Architecture Support**: Multi-architecture file path analysis

**Usage:**
```bash
# Run all tests
python3 tests/test_vex_kernel_checker.py

# Run with verbose output
python3 tests/test_vex_kernel_checker.py -v

# Run specific test class
python3 -m unittest tests.test_vex_kernel_checker.TestVexKernelChecker -v
```

### 2. Test Runner (`run_tests.py`)

Advanced test runner with additional features:
- **Coverage Reporting**: Generate code coverage reports
- **Test Discovery**: Automatic test discovery and execution
- **Dependency Checking**: Verify required packages are installed
- **Quick Smoke Tests**: Fast validation of basic functionality

**Usage:**
```bash
# Run all tests
python3 tests/run_tests.py

# Run with coverage reporting
python3 tests/run_tests.py --coverage

# Run specific test pattern
python3 tests/run_tests.py --pattern "test_initialization"

# Quick smoke test
python3 tests/run_tests.py --quick

# Check dependencies only
python3 tests/run_tests.py --check-deps
```

### 3. Performance Benchmarking (`benchmark.py`)

Comprehensive performance testing suite:
- **Configuration Analysis**: Benchmark Makefile and source file analysis
- **VEX Processing**: Test performance with different dataset sizes
- **Caching Performance**: Measure cache hit rates and performance improvements
- **Memory Usage**: Track memory consumption during operations
- **Parallel Processing**: Evaluate concurrent processing capabilities

**Features:**
- Multiple test datasets (small, medium, large)
- Realistic kernel source structure simulation
- Memory usage tracking with `tracemalloc`
- Statistical analysis of performance metrics
- Detailed reporting with insights and recommendations

**Usage:**
```bash
# Run full benchmark suite
python3 tests/benchmark.py

# Quiet mode (less verbose output)
python3 tests/benchmark.py --quiet

# Custom iterations per test
python3 tests/benchmark.py --iterations 5

# Save results to JSON
python3 tests/benchmark.py --output benchmark_results.json
```

### 4. Configuration Validation (`validate_config.py`)

Comprehensive validation tool for user environments:
- **Python Environment**: Version compatibility and package availability
- **File Validation**: VEX file format, kernel config syntax, source structure
- **WebDriver Setup**: Edge WebDriver accessibility and version checking
- **API Configuration**: NVD API key validation
- **Tool Accessibility**: VEX Kernel Checker import and functionality verification

**Features:**
- Detailed validation reports with actionable recommendations
- JSON output for automated testing
- Support for both full and limited functionality modes
- Clear status indicators (✅ ❌ ⚠️ ℹ️)

**Usage:**
```bash
# Basic validation
python3 tests/validate_config.py \
  --vex-file examples/test_real_cve.json \
  --kernel-config /path/to/.config \
  --kernel-source /path/to/kernel/source

# Full configuration with WebDriver and API key
python3 tests/validate_config.py \
  --vex-file examples/test_real_cve.json \
  --kernel-config /path/to/.config \
  --kernel-source /path/to/kernel/source \
  --webdriver /path/to/msedgedriver \
  --api-key your-nvd-api-key

# Quiet mode (show only failures)
python3 tests/validate_config.py --quiet [options...]

# Save results to JSON
python3 tests/validate_config.py --json-output validation_results.json [options...]
```

## Test Categories

### Unit Tests
- **Initialization**: Test VEX Kernel Checker instantiation and configuration
- **Configuration Parsing**: Validate kernel config file processing
- **Pattern Matching**: Test regex patterns for CONFIG option detection
- **Data Validation**: Ensure VEX data structure validation works correctly

### Integration Tests
- **End-to-End Workflows**: Complete analysis workflows from VEX input to results
- **File System Integration**: Real file operations with temporary test environments
- **Mock API Testing**: Simulated CVE API responses and error handling
- **Cache Integration**: Multi-layer caching system validation

### Performance Tests
- **Scalability**: Performance with varying dataset sizes (10-200 CVEs)
- **Memory Efficiency**: Memory usage patterns and leak detection
- **Caching Effectiveness**: Cache hit rates and performance improvements
- **Concurrent Operations**: Multi-threaded processing capabilities

### Validation Tests
- **Environment Compatibility**: Python version and dependency checking
- **File Format Validation**: VEX, kernel config, and source file format verification
- **External Tool Integration**: WebDriver and API connectivity validation

## Running Tests in Different Environments

### Development Environment
```bash
# Quick validation during development
python3 tests/run_tests.py --quick

# Run tests with coverage for code quality
python3 tests/run_tests.py --coverage
```

### CI/CD Pipeline
```bash
# Automated testing with JSON output
python3 tests/run_tests.py --quiet
python3 tests/validate_config.py --json-output ci_validation.json [...]
```

### Performance Analysis
```bash
# Comprehensive performance analysis
python3 tests/benchmark.py --output performance_baseline.json

# Compare performance across changes
python3 tests/benchmark.py --iterations 10 --output new_performance.json
```

### User Environment Validation
```bash
# Help users validate their setup
python3 tests/validate_config.py [user-specific-options]
```

## Test Data

The test suite creates realistic test environments including:
- **Kernel Source Structure**: Simulated Linux kernel directory structure with drivers, fs, net, etc.
- **Makefile Patterns**: Realistic Makefile and Kbuild files with CONFIG dependencies
- **Source Code Patterns**: C source files with various CONFIG usage patterns
- **VEX Data Sets**: Small (10 CVEs), medium (50 CVEs), and large (200 CVEs) test datasets
- **Configuration Files**: Minimal and full kernel configuration examples

## Dependencies

Required packages for full testing functionality:
- `unittest` (built-in)
- `selenium` (for WebDriver testing)
- `requests` (for API simulation)
- `psutil` (for performance monitoring)
- `coverage` (optional, for coverage reporting)

Install with:
```bash
pip3 install -r requirements.txt
pip3 install coverage psutil  # Additional test dependencies
```

## Continuous Integration

The test suite is designed to work well in CI/CD environments:
- Exit codes indicate test success/failure
- JSON output for automated result processing
- Quiet modes for clean CI logs
- Dependency validation before test execution

Example CI usage:
```bash
# Validate environment
python3 tests/validate_config.py --quiet --json-output ci_validation.json [...]

# Run tests with coverage
python3 tests/run_tests.py --coverage --quiet

# Performance regression testing
python3 tests/benchmark.py --quiet --output ci_performance.json
```

## Contributing to Tests

When adding new features to VEX Kernel Checker:

1. **Add Unit Tests**: Cover new functionality in `test_vex_kernel_checker.py`
2. **Update Integration Tests**: Ensure end-to-end workflows include new features
3. **Add Performance Tests**: Include performance benchmarks for significant new features
4. **Update Validation**: Add configuration validation for new requirements

### Test Writing Guidelines

- Use descriptive test method names: `test_kernel_config_analysis_with_missing_configs`
- Include both positive and negative test cases
- Test error conditions and edge cases
- Use temporary files/directories for file system tests
- Clean up resources in `tearDown()` methods
- Add performance benchmarks for computationally intensive features

## Troubleshooting

### Common Issues

**Import Errors**:
```bash
# Ensure VEX Kernel Checker is importable
python3 tests/validate_config.py --vex-file examples/test_real_cve.json [...]
```

**Missing Dependencies**:
```bash
# Check and install missing packages
python3 tests/run_tests.py --check-deps
```

**Performance Issues**:
```bash
# Analyze performance bottlenecks
python3 tests/benchmark.py --verbose
```

**WebDriver Issues**:
```bash
# Validate WebDriver setup
python3 tests/validate_config.py --webdriver /path/to/msedgedriver [...]
```

### Test Environment Issues

If tests fail due to environment issues:
1. Check Python version compatibility (3.7+)
2. Verify all required packages are installed
3. Ensure file permissions allow test file creation
4. Check available disk space for temporary test files

## Test Coverage Goals

The test suite aims for:
- **Code Coverage**: >90% line coverage of core functionality
- **Branch Coverage**: >85% branch coverage for decision points
- **Integration Coverage**: All major user workflows tested
- **Error Coverage**: All error conditions and edge cases tested
- **Performance Coverage**: All performance-critical methods benchmarked

Current coverage can be checked with:
```bash
python3 tests/run_tests.py --coverage
```

This will generate an HTML coverage report in `htmlcov/index.html` for detailed analysis.
