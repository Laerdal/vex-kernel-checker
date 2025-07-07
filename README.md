# VEX Kernel Checker

**A sophisticated tool for analyzing CVE vulnerabilities against Linux kernel configurations**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub release](https://img.shields.io/github/v/release/Laerdal/vex-kernel-checker)](https://github.com/Laerdal/vex-kernel-checker/releases)
[![Tests](https://github.com/Laerdal/vex-kernel-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/Laerdal/vex-kernel-checker/actions)

## Overview

VEX Kernel Checker is an advanced vulnerability analysis tool that correlates CVE (Common Vulnerabilities and Exposures) data with Linux kernel configurations to determine whether specific vulnerabilities affect a given kernel build. It processes VEX (Vulnerability Exploitability eXchange) files and provides automated analysis of vulnerability impact based on:

- **Kernel configuration analysis** - Maps CVEs to required CONFIG options
- **Patch analysis** - Extracts source files from security patches 
- **Makefile parsing** - Analyzes build system dependencies
- **Architecture awareness** - Considers target architecture implications

## Project Structure

```
vex-kernel-checker/
├── vex-kernel-checker.py          # Main CLI application (modular implementation)
├── vex_kernel_checker/            # Modular Python package
│   ├── __init__.py                # Package initialization
│   ├── common.py                  # Shared data structures and utilities
│   ├── base.py                    # Base classes and performance tracking
│   ├── cve_manager.py             # CVE data fetching and management
│   ├── config_analyzer.py         # Kernel configuration analysis
│   ├── vulnerability_analyzer.py  # Core vulnerability analysis logic
│   ├── patch_manager.py           # Patch fetching and analysis
│   ├── architecture_manager.py    # Architecture-specific logic
│   ├── report_generator.py        # VEX report generation
│   └── main_checker.py            # Main orchestration logic
├── tests/                         # Clean, comprehensive test suite
│   ├── run_tests.py               # Modern test runner with coverage
│   ├── test_common.py             # Tests for shared utilities
│   ├── test_base.py               # Tests for base functionality
│   ├── test_cve_manager.py        # CVE management tests
│   ├── test_config_analyzer.py    # Configuration analysis tests
│   ├── test_vulnerability_analyzer.py  # Core analysis tests
│   ├── test_patch_manager.py      # Patch management tests
│   ├── test_architecture_manager.py    # Architecture tests
│   ├── test_report_generator.py   # Report generation tests
│   └── test_integration.py        # End-to-end integration tests
├── examples/                      # Sample data and configurations
│   ├── README.md                  # Usage examples
│   ├── test_demo.config           # Sample kernel config
│   ├── test_vex.json              # Sample VEX file
│   └── [other samples]           # Test data and examples
├── docs/                          # Comprehensive documentation
├── scripts/                       # Development and utility scripts
├── README.md                      # Project documentation
├── requirements.txt               # Python dependencies
├── Dockerfile                     # Container build configuration
├── Makefile                       # Build and test automation
└── [other config files]          # Project configuration
```

## Key Features

### 🚀 **Performance Optimized**
- Multi-level caching system (Makefile, config, source analysis)
- Parallel processing for large vulnerability datasets
- Smart search ordering and aggressive optimization
- Cache hit/miss tracking with performance statistics

### 🔍 **Comprehensive Analysis**
- **Kernel CVE filtering**: Automatically identifies and analyzes only kernel-related CVEs (use `--analyze-all-cves` to override)
- **GitHub-prioritized patch analysis**: Fetches and analyzes security patches with GitHub as the primary source for reliability
- **Config-only fallback**: Graceful degradation when patch data unavailable
- **Makefile intelligence**: Recursive parsing with variable expansion
- **Architecture filtering**: ARM-focused analysis with multi-arch support

### 🛡️ **Robust & Reliable**
- Thread-safe NVD API rate limiting with exponential backoff
- Comprehensive error handling and validation
- Existing analysis preservation (only modifies with `--reanalyse`)
- Detailed progress reporting with status indicators

### ⚡ **User-Friendly**
- Automatic patch checking when API credentials provided
- Intuitive command-line interface with helpful error messages
- Verbose mode for debugging and development
- Cache management with `--clear-cache` option

### ✅ **Production Ready**
- Comprehensive test suite with >90% code coverage
- Performance benchmarking and optimization tracking
- Configuration validation and environment verification
- Continuous integration with automated quality checks
- MIT licensed with comprehensive documentation

## Installation

### Prerequisites
- Python 3.8 or higher
- Linux environment (tested on Ubuntu/Debian)
- Internet connection for CVE data fetching

### Required Python Packages
```bash
pip install requests selenium beautifulsoup4 lxml
```

### Optional (for full patch checking)
- **NVD API Key**: Register at [NVD API](https://nvd.nist.gov/developers/request-an-api-key)
- **Microsoft Edge WebDriver**: Download from [Microsoft Edge WebDriver](https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/)

## Quick Start

### Basic Usage (Config-only analysis)
```bash
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /boot/config-$(uname -r) \
  --kernel-source /lib/modules/$(uname -r)/build
```

### Full Analysis (with patch checking)
```bash
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /path/to/kernel/.config \
  --kernel-source /path/to/kernel/source \
  --api-key YOUR_NVD_API_KEY \
  --edge-driver /path/to/msedgedriver \
  --verbose
```

### Re-analyze Existing Results
```bash
python3 vex-kernel-checker.py \
  --vex-file vulnerabilities.json \
  --kernel-config /path/to/.config \
  --kernel-source /path/to/source \
  --reanalyse \
  --output updated_vulnerabilities.json
```

## Command Line Options

| Option | Description | Required |
|--------|-------------|----------|
| `--vex-file` | Path to VEX JSON file | ✅ |
| `--kernel-config` | Path to kernel config file (.config) | ✅ |
| `--kernel-source` | Path to kernel source directory | ✅ |
| `--output` | Output file path (default: update in place) | ❌ |
| `--reanalyse` | Re-analyze CVEs with existing analysis | ❌ |
| `--cve-id` | Process only specific CVE ID | ❌ |
| `--verbose` | Enable detailed logging | ❌ |
| `--config-only` | Disable patch checking (faster) | ❌ |
| `--api-key` | NVD API key for patch analysis | ❌ |
| `--edge-driver` | Path to Edge WebDriver executable | ❌ |
| `--clear-cache` | Clear all internal caches | ❌ |
| `--performance-stats` | Show detailed performance metrics | ❌ |
| `--analyze-all-cves` | Analyze all CVEs (default: kernel-related only) | ❌ |

## Analysis Methods

### 1. Patch-Based Analysis (Most Accurate)
When NVD API key and WebDriver are available:
1. Fetches CVE details from NVD API
2. Extracts patch URLs from CVE references, **prioritizing GitHub sources**
3. Downloads patch content using optimized fetching strategy:
   - **GitHub direct access** (fastest, most reliable)
   - GitHub alternatives using extracted commit IDs
   - Original URLs with Selenium WebDriver fallback
   - Other patch repositories (kernel.org, lore.kernel.org) as last resort
4. Analyzes affected source files and configuration dependencies
5. Maps to kernel configuration options

### 2. Config-Only Analysis (Fallback)
When patch data is unavailable:
1. Fetches basic CVE information
2. Performs heuristic analysis based on CVE metadata
3. Provides conservative assessment requiring manual review

## VEX File Format

Input VEX files should follow this structure:
```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2023-XXXXX",
      "details": "Vulnerability description",
      "analysis": {
        "state": "not_affected|affected|under_investigation",
        "justification": "component_not_present|requires_configuration|...",
        "detail": "Detailed analysis explanation",
        "timestamp": "2025-01-01T12:00:00Z"
      }
    }
  ]
}
```

### Analysis States
- **`not_affected`**: Vulnerability does not affect this kernel configuration
- **`affected`**: Vulnerability affects this kernel configuration
- **`under_investigation`**: Manual review required

### Justification Types
- **`component_not_present`**: Vulnerable component not compiled
- **`vulnerable_code_not_present`**: Vulnerable code not included
- **`requires_configuration`**: Specific configuration needed for vulnerability

## Performance & Caching

The tool implements sophisticated caching for optimal performance:

- **Makefile Cache**: Parsed Makefile content and variables
- **Config Cache**: Resolved configuration option mappings
- **Source Analysis Cache**: Source file analysis results
- **Path Cache**: File path resolution results

### Cache Statistics
Run with `--performance-stats` to see cache hit rates and timing information:
```
Cache Performance:
  makefile: 145 hits, 23 misses (86.3% hit rate)
  config: 89 hits, 15 misses (85.6% hit rate)
  Overall Cache Hit Rate: 86.1%
```

## Architecture Support

Primary focus on ARM architectures with support for:
- ARM32 (arm)
- ARM64 (aarch64, arm64)
- Limited x86/x86_64 support

Architecture-specific configuration options are automatically filtered.

## Error Handling

The tool provides comprehensive error handling:
- **Network failures**: Automatic retry with exponential backoff
- **API rate limiting**: Thread-safe rate limiting with global coordination
- **Missing files**: Clear error messages with suggestions
- **Invalid configurations**: Validation with helpful diagnostics
- **Bot detection**: Automatic fallback to alternative patch sources

### Bot Detection and Access Issues

When accessing patch repositories, you may encounter access restrictions. The tool uses an optimized **GitHub-first strategy** to minimize these issues:

1. **Prioritizes GitHub sources** - Direct access without bot detection issues
2. **Extracts commit IDs** - Converts other URLs to reliable GitHub alternatives  
3. **Detects bot protection pages** (Cloudflare, "Just a moment", etc.)
4. **Tries multiple fallback sources** (kernel.org, lore.kernel.org) as last resort
5. **Falls back gracefully** to config-only analysis when needed

The GitHub-first approach significantly reduces bot detection issues while providing faster and more reliable patch access.

For detailed troubleshooting, see [docs/BOT_DETECTION.md](docs/BOT_DETECTION.md).

## Testing and Quality Assurance

VEX Kernel Checker includes a comprehensive testing framework to ensure reliability and performance:

### Quick Testing
```bash
# Run quick smoke tests
make test-quick

# Validate your configuration
make validate VEX_FILE=examples/test_real_cve.json KERNEL_CONFIG=/path/to/.config KERNEL_SOURCE=/path/to/kernel
```

### Development Testing
```bash
# Run full test suite with coverage
make test-coverage

# Run performance benchmarks
make benchmark

# Format code and run quality checks
make workflow-fix
```

### Test Categories
- **Unit Tests**: Core functionality, configuration analysis, pattern matching
- **Integration Tests**: End-to-end workflows, file system operations
- **Performance Tests**: Scalability testing with datasets up to 200 CVEs
- **Validation Tests**: Environment setup, configuration verification

### Quality Metrics
- Code coverage: >90% target
- Performance benchmarking for all major operations
- Automated configuration validation
- Cross-platform compatibility testing

See [`docs/TESTING.md`](docs/TESTING.md) for comprehensive testing documentation.

## Contributing

We welcome contributions from the cybersecurity and Linux kernel communities! 

### Getting Started
- 🐛 **Report bugs** via [GitHub Issues](https://github.com/Laerdal/vex-kernel-checker/issues)
- 💡 **Suggest features** through feature requests
- 🔧 **Submit pull requests** following our [Contributing Guidelines](CONTRIBUTING.md)
- 📖 **Improve documentation** and examples

### Development Areas
- Additional architecture support (RISC-V, PowerPC, etc.)
- Enhanced patch parsing algorithms
- Performance optimizations
- Integration with CI/CD pipelines
- Web-based interface development
- Additional vulnerability database support

For detailed contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Repository

**GitHub**: [https://github.com/Laerdal/vex-kernel-checker](https://github.com/Laerdal/vex-kernel-checker)
**Issues**: [https://github.com/Laerdal/vex-kernel-checker/issues](https://github.com/Laerdal/vex-kernel-checker/issues)
**Releases**: [https://github.com/Laerdal/vex-kernel-checker/releases](https://github.com/Laerdal/vex-kernel-checker/releases)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- **Karsten S. Opdal (karsten.s.opdal@gmail.com)** - Initial work and ongoing development
- **AI Assistant** - Architecture design and optimization contributions

## Acknowledgments

- **National Vulnerability Database (NVD)** for CVE data
- **Linux Kernel Community** for patch information
- **MITRE Corporation** for CVE standards
- **VEX Working Group** for vulnerability exchange format

## Troubleshooting

### Common Issues

**"Patch checking disabled"**
- Ensure both `--api-key` and `--edge-driver` are provided
- Verify WebDriver is executable: `chmod +x /path/to/msedgedriver`

**Rate limiting errors**
- NVD API has rate limits (10 requests/minute without key, 50/minute with key)
- Tool automatically handles rate limiting with delays

**WebDriver issues**
- Ensure Microsoft Edge browser is installed
- Download WebDriver version matching your Edge browser version
- Check WebDriver permissions and path

**Performance issues**
- Use `--config-only` for faster analysis
- Clear caches periodically with `--clear-cache`
- Monitor cache hit rates with `--performance-stats`

## Roadmap

- [ ] Web-based interface for easier access
- [ ] Integration with CI/CD pipelines
- [ ] Support for additional vulnerability databases
- [ ] Enhanced reporting and visualization
- [ ] Container-based deployment options
