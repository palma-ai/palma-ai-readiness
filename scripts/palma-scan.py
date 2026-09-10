#!/usr/bin/env python3
"""One local entry point; no installation or third-party dependencies."""
import sys
from pathlib import Path

if sys.version_info < (3, 11):
    print("Palma needs Python 3.11 or newer. No packages need to be installed.", file=sys.stderr)
    raise SystemExit(2)

# -I -S excludes ambient module paths. Add only the directory of this trusted script.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from palma_scan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
