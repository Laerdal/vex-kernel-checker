# Contributing to VEX Kernel Checker

We welcome contributions to the VEX Kernel Checker project! This document provides guidelines for contributing to help maintain code quality and consistency.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Community Guidelines](#community-guidelines)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic understanding of vulnerability analysis and Linux kernel concepts

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/vex-kernel-checker.git
   cd vex-kernel-checker
   ```

2. **Set Up Development Environment**
   ```bash
   # Create virtual environment
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Install development dependencies
   pip install pytest pytest-cov black flake8 mypy
   ```

3. **Verify Setup**
   ```bash
   # Run tests
   make test
   
   # Run the tool
   python3 vex-kernel-checker.py --help
   ```

## Contribution Guidelines

### Types of Contributions

We welcome several types of contributions:

- **Bug fixes** - Fixing issues with existing functionality
- **Feature enhancements** - Adding new capabilities
- **Documentation improvements** - Better docs, examples, tutorials
- **Performance optimizations** - Making the tool faster or more efficient
- **Test coverage** - Adding or improving tests
- **Architecture support** - Support for additional CPU architectures
- **Integration helpers** - Scripts, CI/CD improvements, packaging

### Before You Start

1. **Check existing issues** - Look for related bugs or feature requests
2. **Create an issue** - Discuss significant changes before implementing
3. **Keep scope focused** - Smaller, focused changes are easier to review
4. **Follow conventions** - Maintain consistency with existing code

## Code Style

### Python Code Standards

- **PEP 8 compliance** - Use `black` for formatting
- **Type hints** - Add type annotations for new functions
- **Docstrings** - Document all public functions and classes
- **Error handling** - Robust exception handling with informative messages
- **Performance** - Consider caching and optimization for hot paths

### Example Function

```python
def analyze_vulnerability(cve_id: str, config_options: Set[str]) -> VulnerabilityAnalysis:
    """Analyze a CVE against kernel configuration.
    
    Args:
        cve_id: CVE identifier (e.g., "CVE-2023-1234")
        config_options: Set of enabled kernel config options
        
    Returns:
        VulnerabilityAnalysis object with assessment results
        
    Raises:
        ValueError: If CVE ID format is invalid
        NetworkError: If CVE data cannot be fetched
    """
    if not cve_id.startswith("CVE-"):
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    
    # Implementation...
    return analysis_result
```

### Documentation Standards

- **Clear and concise** - Write for both technical and non-technical users
- **Examples included** - Provide practical usage examples
- **Up-to-date** - Keep documentation synchronized with code changes
- **Markdown formatting** - Follow consistent formatting in .md files

## Testing

### Test Requirements

- **Unit tests** - Test individual functions and methods
- **Integration tests** - Test end-to-end workflows
- **Performance tests** - Verify performance regression protection
- **Edge cases** - Test error conditions and boundary cases

### Running Tests

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test file
python3 -m pytest tests/test_specific_module.py -v

# Run performance benchmarks
make benchmark
```

### Writing Tests

```python
import unittest
from unittest.mock import Mock, patch
from your_module import VexKernelChecker

class TestVexKernelChecker(unittest.TestCase):
    def setUp(self):
        self.checker = VexKernelChecker(verbose=False)
    
    def test_cve_validation(self):
        """Test CVE ID validation logic."""
        # Valid CVE
        self.assertTrue(self.checker.is_valid_cve_id("CVE-2023-1234"))
        
        # Invalid CVE
        with self.assertRaises(ValueError):
            self.checker.is_valid_cve_id("INVALID-2023-1234")
    
    @patch('requests.get')
    def test_cve_fetching(self, mock_get):
        """Test CVE data fetching with mocked API."""
        mock_response = Mock()
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response
        
        result = self.checker.fetch_cve_details("CVE-2023-1234")
        self.assertIsNotNone(result)
```

## Pull Request Process

### Before Submitting

1. **Update from main** - Rebase your branch on latest main
2. **Run tests** - Ensure all tests pass
3. **Code quality** - Run linting and formatting tools
4. **Documentation** - Update docs for any API changes
5. **Changelog** - Add entry to CHANGELOG.md for significant changes

### PR Requirements

- **Clear title** - Descriptive title explaining the change
- **Detailed description** - What, why, and how of the changes
- **Test coverage** - Include tests for new functionality
- **Breaking changes** - Clearly mark any breaking changes
- **Screenshots** - Include screenshots for UI changes

### PR Template

```markdown
## Summary
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Code refactoring

## Changes Made
- Detailed list of changes
- Another change

## Testing
- [ ] Tests pass locally
- [ ] New tests added for changes
- [ ] Manual testing completed

## Documentation
- [ ] Documentation updated
- [ ] Code comments added
- [ ] Examples updated

## Breaking Changes
List any breaking changes and migration path
```

### Review Process

1. **Automated checks** - CI/CD pipeline must pass
2. **Code review** - At least one maintainer review required
3. **Testing** - Reviewers may test changes locally
4. **Discussion** - Address feedback and questions promptly
5. **Approval** - Merge after approval and passing checks

## Issue Reporting

### Bug Reports

Use the bug report template:

```markdown
**Describe the bug**
Clear description of the issue

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. With configuration '...'
3. See error

**Expected behavior**
What should have happened

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Python version: [e.g., 3.9]
- Tool version: [e.g., 1.0.0]

**Additional context**
Any other relevant information
```

### Feature Requests

Use the feature request template:

```markdown
**Is your feature request related to a problem?**
Description of the problem

**Describe the solution you'd like**
Clear description of desired feature

**Describe alternatives you've considered**
Alternative solutions or workarounds

**Additional context**
Any other relevant information
```

## Community Guidelines

### Code of Conduct

- **Be respectful** - Treat all contributors with respect
- **Be inclusive** - Welcome people of all backgrounds
- **Be constructive** - Provide helpful feedback
- **Be patient** - Allow time for responses and reviews

### Communication

- **GitHub issues** - For bugs, features, and questions
- **Discussions** - For general questions and ideas
- **Email** - For security issues (see SECURITY.md)

### Recognition

Contributors are recognized in:
- AUTHORS file
- Release notes
- Documentation acknowledgments
- Annual contributor highlights

## Getting Help

If you need help:

1. **Check documentation** - README, docs/ folder
2. **Search issues** - Someone may have asked the same question
3. **Create discussion** - For questions and ideas
4. **Contact maintainers** - For urgent issues

Thank you for contributing to VEX Kernel Checker!
