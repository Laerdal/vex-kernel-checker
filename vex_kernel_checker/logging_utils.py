"""
Centralized logging utilities for VEX Kernel Checker.

This module provides consistent logging configuration and utilities
for all components in the VEX Kernel Checker package.
"""

import logging
import sys
from typing import Optional


class VexKernelCheckerLogger:
    """Centralized logger configuration for the VEX Kernel Checker package."""

    _configured = False
    _verbose = False
    _log_file = None

    @classmethod
    def configure(cls, verbose: bool = False, log_file: Optional[str] = None):
        """
        Configure logging for the entire VEX Kernel Checker package.

        Args:
            verbose: Enable verbose (DEBUG) logging
            log_file: Optional file path for log output
        """
        cls._verbose = verbose
        cls._log_file = log_file

        # Set logging level
        level = logging.DEBUG if verbose else logging.INFO

        # Create formatters
        if verbose:
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
            )
        else:
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

        # Create handlers
        handlers = []

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        handlers.append(console_handler)

        # File handler (if specified)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            handlers.append(file_handler)

        # Configure root logger for the package
        package_logger = logging.getLogger("vex_kernel_checker")
        package_logger.setLevel(level)

        # Remove existing handlers to avoid duplicates
        for handler in package_logger.handlers[:]:
            package_logger.removeHandler(handler)

        # Add new handlers
        for handler in handlers:
            package_logger.addHandler(handler)

        # Prevent propagation to avoid duplicate messages
        package_logger.propagate = False

        cls._configured = True

        if verbose:
            package_logger.debug(
                "Verbose logging enabled for VEX Kernel Checker package"
            )

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Get a logger instance for a specific component.

        Args:
            name: Name of the component (usually __name__)

        Returns:
            Configured logger instance
        """
        # Ensure package logging is configured
        if not cls._configured:
            cls.configure()

        # Return logger with package prefix
        if name.startswith("vex_kernel_checker"):
            return logging.getLogger(name)
        else:
            return logging.getLogger(f"vex_kernel_checker.{name}")

    @classmethod
    def is_verbose(cls) -> bool:
        """Check if verbose logging is enabled."""
        return cls._verbose


def get_logger(name: str) -> logging.Logger:
    """
    Convenience function to get a logger instance.

    Args:
        name: Name of the component (usually __name__)

    Returns:
        Configured logger instance
    """
    return VexKernelCheckerLogger.get_logger(name)


def configure_logging(verbose: bool = False, log_file: Optional[str] = None):
    """
    Convenience function to configure logging.

    Args:
        verbose: Enable verbose (DEBUG) logging
        log_file: Optional file path for log output
    """
    VexKernelCheckerLogger.configure(verbose, log_file)


def is_verbose() -> bool:
    """Check if verbose logging is enabled."""
    return VexKernelCheckerLogger.is_verbose()
