#!/usr/bin/env python3
"""One local entry point; no installation or third-party dependencies."""
import os
import sys

if sys.version_info < (3, 11):
    print("Palma needs Python 3.11 or newer. No packages need to be installed.", file=sys.stderr)
    raise SystemExit(2)
# Isolated mode ignores PYTHONPATH, user site-packages and this folder on the module path, so
# nothing planted beside the scripts can load before the release check below.
if not (sys.flags.isolated and sys.flags.no_site):
    print("Palma: run this with python -I -S, for example: python3 -I -S scripts/palma-scan.py run", file=sys.stderr)
    raise SystemExit(2)

import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
# build_release.py sets this to True in published releases: a release without its manifest is refused.
RELEASE = False
# Operating-system metadata files a file manager can add; they are never imported.
OS_METADATA = {".DS_Store", "Thumbs.db", "desktop.ini"}


def changed_release_file():
    """The first file that differs from the release manifest, or None.

    Runs before any skill code is imported. It catches incomplete, mixed or edited
    copies of a release; it is not a signature, so the downloaded archive is still
    verified against its published checksum. A source checkout has no manifest. Every file
    under scripts/ must be listed, so planted bytecode or modules are refused too.
    """
    release = HERE.parent
    manifest = release / "MANIFEST.sha256"
    if not manifest.is_file():
        return "MANIFEST.sha256" if RELEASE else None
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
    folders = {parent.as_posix() for name in listed for parent in Path(name).parents}
    for folder, directories, names in os.walk(HERE):
        for directory in directories:
            relative = (Path(folder) / directory).relative_to(release).as_posix()
            if relative not in folders or (Path(folder) / directory).is_symlink():
                return relative
        for file_name in names:
            relative = (Path(folder) / file_name).relative_to(release).as_posix()
            if relative not in listed and file_name not in OS_METADATA and not file_name.startswith("._"):
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
