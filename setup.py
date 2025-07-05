#!/usr/bin/env python3
"""
Setup script for VEX Kernel Checker
"""

from setuptools import setup, find_packages
import os

# Read the README file for the long description
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements from requirements.txt
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vex-kernel-checker",
    version="1.0.0",
    author="Laerdal Medical",
    author_email="support@laerdal.com",
    description="A sophisticated tool for analyzing CVE vulnerabilities against Linux kernel configurations",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/laerdal/vex-kernel-checker",
    project_urls={
        "Bug Reports": "https://github.com/laerdal/vex-kernel-checker/issues",
        "Source": "https://github.com/laerdal/vex-kernel-checker",
        "Documentation": "https://github.com/laerdal/vex-kernel-checker/blob/main/README.md",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "Topic :: System :: Operating System Kernels :: Linux",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "vex-kernel-checker=vex_kernel_checker:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["README.md", "LICENSE", "requirements.txt"],
    },
    keywords="cve vulnerability linux kernel security vex",
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=0.5",
        ],
    },
)
