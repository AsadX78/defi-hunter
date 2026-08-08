"""Pytest root config: ensures the package is importable without install."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
