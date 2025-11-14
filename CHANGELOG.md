# Changelog

All notable changes to VEX Kernel Checker will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Driver-specific CONFIG detection** - Extracts specific driver CONFIG options (e.g., `CONFIG_DRM_XE`, `CONFIG_USB_NET_LAN78XX`) from CVE descriptions to avoid false positives from broad parent configs
- **Unanalyzed CVE tracking** - Separate reporting category for CVEs that haven't been analyzed yet, distinct from "in_triage"
- Preparation for standalone repository release

### Fixed
- False positives where CVEs for specific drivers were marked as exploitable based only on parent CONFIG options (e.g., xe driver CVEs marked exploitable because CONFIG_DRM was enabled)
- Misleading "in_triage" count that included unanalyzed CVEs; now properly categorized as "unanalyzed"

### Changed
- Improved report clarity by distinguishing between "In Triage" (analyzed but needs manual review) and "Unanalyzed" (not yet analyzed)
- **Path resolution in config files**: Output and log file paths are now relative to current working directory (where command is executed), while input file paths remain relative to config file location

## [1.0.0] - 2025-07-05

### Added
- **GitHub-prioritized patch fetching** - Prioritizes GitHub sources for better reliability and speed
- **Comprehensive CVE analysis** with kernel-specific filtering
- **Multi-level caching system** for optimal performance (Makefile, config, source analysis)
- **Parallel processing** support for large vulnerability datasets
- **Smart search ordering** and aggressive optimization
- **Thread-safe NVD API rate limiting** with exponential backoff
- **Comprehensive error handling** and validation
- **Performance benchmarking** and optimization tracking
- **Configuration validation** and environment verification
- **Continuous integration** with automated quality checks
- **Architecture filtering** - ARM-focused analysis with multi-arch support
- **Bot detection handling** for patch repository access
- **Cache management** with `--clear-cache` option
- **Detailed progress reporting** with status indicators
- **Verbose mode** for debugging and development

### Features
- **Patch-based analysis** - Fetches and analyzes security patches from NVD API
- **Config-only fallback** - Graceful degradation when patch data unavailable
- **Makefile intelligence** - Recursive parsing with variable expansion
- **Existing analysis preservation** - Only modifies with `--reanalyse`
- **Kernel CVE filtering** - Automatically identifies kernel-related CVEs
- **Alternative patch sources** - Multiple fallback strategies for patch retrieval

### Testing
- **Comprehensive test suite** with >90% code coverage target
- **Unit tests** - Core functionality, configuration analysis, pattern matching
- **Integration tests** - End-to-end workflows, file system operations
- **Performance tests** - Scalability testing with datasets up to 200 CVEs
- **Validation tests** - Environment setup, configuration verification
- **Automated benchmarking** for all major operations
- **Cross-platform compatibility** testing (Python 3.8-3.11)

### Documentation
- **Comprehensive README** with usage examples and troubleshooting
- **Testing documentation** - Complete guide for all testing frameworks
- **API documentation** - Detailed method and class documentation
- **Bot detection guide** - Troubleshooting for patch access issues
- **Performance optimization** guide
- **Architecture support** documentation

### Quality Assurance
- **MIT licensed** with comprehensive documentation
- **Production-ready** error handling and validation
- **Performance monitoring** with cache hit/miss tracking
- **Memory usage tracking** and optimization
- **Automated quality gates** and formatting validation
- **Security best practices** implementation

### Dependencies
- Python 3.8+ support
- requests - HTTP library for API calls
- selenium - WebDriver for dynamic content
- beautifulsoup4 - HTML parsing
- lxml - XML/HTML parser

### Architecture Support
- ARM32 (arm) - Primary focus
- ARM64 (aarch64, arm64) - Primary focus  
- x86/x86_64 - Limited support

## [0.9.0] - 2025-07-04

### Added
- Initial kernel configuration analysis
- Basic CVE fetching from NVD API
- Simple patch analysis capabilities
- Makefile parsing functionality

### Changed
- Improved error handling
- Enhanced logging capabilities

## [0.8.0] - 2025-07-03

### Added
- VEX file format support
- Basic vulnerability analysis framework
- Configuration option extraction

---

## Version History Summary

- **v1.0.0** - Production release with GitHub prioritization and comprehensive testing
- **v0.9.x** - Beta releases with core functionality
- **v0.8.x** - Alpha releases with basic framework

## Migration Notes

### From v0.9.x to v1.0.0
- **GitHub prioritization** - Patch fetching now prioritizes GitHub sources automatically
- **Enhanced caching** - New multi-level caching system improves performance significantly
- **Improved testing** - Comprehensive test suite with automated benchmarking
- **Better error handling** - More robust error recovery and user-friendly messages

### Breaking Changes
- None - v1.0.0 maintains backward compatibility with v0.9.x

## Future Roadmap

### v1.1.0 (Planned)
- Web-based interface for easier access
- Enhanced reporting and visualization
- Additional architecture support (RISC-V, MIPS)

### v1.2.0 (Planned)
- Integration with CI/CD pipelines
- Support for additional vulnerability databases
- Container-based deployment options

### v2.0.0 (Future)
- Real-time vulnerability monitoring
- Machine learning-based analysis improvements
- Enterprise features and scaling
