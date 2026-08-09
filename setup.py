#!/usr/bin/env python3
"""Setup script for DeFi Hunter"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="defi-hunter",
    version="1.3.5",
    author="DeFi Hunter Community",
    description="Open Source DeFi Security Analysis Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/defi-hunter/defi-hunter",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0",
        "requests>=2.28",
        "pyyaml>=6.0",
        "rich>=13.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "black>=22.0",
            "flake8>=5.0",
        ],
        "reports": [
            "jinja2>=3.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "defihunter=defihunter.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
