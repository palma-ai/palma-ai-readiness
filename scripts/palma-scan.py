#!/usr/bin/env python3
"""One local entry point; no installation or third-party dependencies."""
import hashlib
import os
from pathlib import Path
import sys

if sys.version_info < (3, 11):
    print("Palma needs Python 3.11 or newer. No packages need to be installed.", file=sys.stderr)
    raise SystemExit(2)

HERE = Path(__file__).resolve().parent


def changed_release_file():
    """The first file that differs from the release manifest, or None.

    Runs before any skill code is imported. It catches incomplete, mixed or edited
    copies of a release; it is not a signature, so the downloaded archive is still
    verified against its published checksum. A source checkout has no manifest.
    """
    release = HERE.parent
    manifest = release / "MANIFEST.sha256"
    if not manifest.is_file():
        return None
    listed = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or Path(name).is_absolute() or ".." in Path(name).parts:
            return "MANIFEST.sha256"
        listed[name] = digest
    for name, digest in listed.items():
        path = release / name
        try:
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                return name
        except OSError:
            return name
    for folder, _, names in os.walk(HERE):
        for file_name in names:
            relative = (Path(folder) / file_name).relative_to(release).as_posix()
            if file_name.endswith(".py") and relative not in listed:
                return relative
    return None


changed = changed_release_file()
if changed:
    print(f"Palma: {changed!r} does not match this release, so nothing was scanned. "
          "Download the skill again from palma.ai and verify its checksum.", file=sys.stderr)
    raise SystemExit(2)

# -I -S excludes ambient module paths. Add only the directory of this trusted script.
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from palma_scan.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
