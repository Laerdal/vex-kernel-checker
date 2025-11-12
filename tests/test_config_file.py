#!/usr/bin/env python3
"""
Test configuration file functionality for VEX Kernel Checker.
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add the parent directory to the path to import the main module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the functions we want to test
from vex_kernel_checker import *

# We need to import the functions from the main script
import subprocess
import json


class TestConfigurationFile(unittest.TestCase):
    """Test configuration file functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_ini_path = os.path.join(self.temp_dir, "test.ini")
        self.config_json_path = os.path.join(self.temp_dir, "test.json")

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def test_create_config_ini(self):
        """Test creating an INI configuration file."""
        result = subprocess.run(
            [
                sys.executable,
                "vex-kernel-checker.py",
                "--create-config",
                self.config_ini_path,
                "--config-format",
                "ini",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(self.config_ini_path))

        # Check that the file contains expected content
        with open(self.config_ini_path, "r") as f:
            content = f.read()
            self.assertIn("[vex-kernel-checker]", content)
            self.assertIn("vex_file =", content)
            self.assertIn("kernel_config =", content)
            self.assertIn("kernel_source =", content)

    def test_create_config_json(self):
        """Test creating a JSON configuration file."""
        result = subprocess.run(
            [
                sys.executable,
                "vex-kernel-checker.py",
                "--create-config",
                self.config_json_path,
                "--config-format",
                "json",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertTrue(os.path.exists(self.config_json_path))

        # Check that the file contains valid JSON
        with open(self.config_json_path, "r") as f:
            config_data = json.load(f)
            self.assertIn("vex_file", config_data)
            self.assertIn("kernel_config", config_data)
            self.assertIn("kernel_source", config_data)

    def test_config_file_validation(self):
        """Test configuration file validation."""
        # Test with non-existent config file
        result = subprocess.run(
            [
                sys.executable,
                "vex-kernel-checker.py",
                "--config",
                "/nonexistent/config.ini",
            ],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Configuration file not found", result.stdout)

    def test_config_help_message(self):
        """Test that help message includes configuration options."""
        result = subprocess.run(
            [sys.executable, "vex-kernel-checker.py", "--help"],
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("--config", result.stdout)
        self.assertIn("--create-config", result.stdout)
        self.assertIn("--config-format", result.stdout)
        self.assertIn("Configuration files can be used", result.stdout)


if __name__ == "__main__":
    unittest.main()
