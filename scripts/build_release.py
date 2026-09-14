#!/usr/bin/env python3
"""Build the standalone website download from an explicit source allowlist."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = ["SKILL.md", "README.md", "THIRD_PARTY_NOTICES.md", "agents/openai.yaml",
             "references/commands.md", "references/declared-report.md",
             "references/report-design.md", "references/risk-rules.md", "references/eu-ai-regulation.md",
             "scripts/palma-scan.py", "scripts/run.sh", "scripts/run.command", "scripts/run.cmd",
             *[f"scripts/palma_scan/{name}.py" for name in
               ("__init__", "cli", "model", "collector", "dedup", "rules", "report", "machine",
                "baseline", "extra_clients", "brands_extra", "governance", "report_theme", "report_font", "report_regulation")],
             "scripts/palma_scan/palma_catalog.json",
             *[f"scripts/palma_scan/engine/{name}.py" for name in
               ("__init__", "collection", "filesystem", "git_provenance", "identity", "observations", "paths",
                "parsing", "redaction", "supplemental_paths", "version", "installations",
                "installation_apps", "installation_codex", "installation_paths",
                "installation_windows", "windows_editors", "windows_packages", "windows_products")],
             *[f"scripts/palma_scan/engine/adapters/{name}.py" for name in
               ("__init__", "artifacts", "configs", "discovery", "mcp", "plugin_components",
                "plugins", "registries", "settings")],
             "scripts/palma_scan/_vendor/__init__.py", "scripts/palma_scan/_vendor/NOTICE.md",
             "scripts/palma_scan/_vendor/sources.json",
             *[f"scripts/palma_scan/_vendor/json5/{name}.py" for name in
               ("__init__", "lib", "parser", "version")],
             *[f"scripts/palma_scan/_vendor/yaml/{name}.py" for name in
               ("__init__", "composer", "constructor", "dumper", "emitter", "error",
                "events", "loader", "nodes", "parser", "reader", "representer",
                "resolver", "scanner", "serializer", "tokens")]]
    checksum = Path(str(args.output) + ".sha256")
    if args.output.exists() or args.output.is_symlink() or checksum.exists() or checksum.is_symlink():
        parser.error("Choose a new output archive; release files are never replaced.")
    contents = []
    for name in sorted(files):
        source = root / name
        if not source.is_file() or source.is_symlink():
            parser.error(f"Missing regular release source: {name}")
        data = source.read_bytes()
        if name.endswith(".cmd"):
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")  # cmd.exe expects CRLF lines.
        contents.append((name, data))
    # Bundled parsers ship only as reviewed: upstream bytes, or the documented local edits.
    vendor = json.loads((root / "scripts/palma_scan/_vendor/sources.json").read_text(encoding="utf-8"))
    reviewed = {**vendor["originalSourceSha256"], **vendor["vendoredSha256"]}
    bundled = {name.removeprefix("scripts/palma_scan/_vendor/"): data for name, data in contents
               if name.startswith("scripts/palma_scan/_vendor/") and name.endswith(".py") and name != "scripts/palma_scan/_vendor/__init__.py"}
    for name in sorted(set(bundled) | set(reviewed)):
        if name not in bundled or hashlib.sha256(bundled[name]).hexdigest() != reviewed.get(name):
            parser.error(f"Bundled parser source does not match its reviewed SHA-256: {name}")
    # The entrypoint checks every file against this manifest before running, and refuses to
    # run a release whose manifest is missing.
    marker = b"\nRELEASE = False\n"
    contents = [(name, data.replace(marker, b"\nRELEASE = True\n") if name == "scripts/palma-scan.py" else data) for name, data in contents]
    if dict(contents)["scripts/palma-scan.py"].count(b"\nRELEASE = True\n") != 1:
        parser.error("The entrypoint's release marker is missing.")
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in contents)
    contents = sorted([*contents, ("MANIFEST.sha256", manifest.encode("ascii"))])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in contents:
            info = zipfile.ZipInfo("palma-ai-readiness/" + name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if name.endswith((".sh", ".command")) else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compresslevel=9)
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    with checksum.open("x", encoding="ascii") as stream:
        stream.write(digest + "  " + args.output.name + "\n")
    print(f"Release: {args.output.resolve()} ({args.output.stat().st_size:,} bytes; {len(contents)} files)")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
