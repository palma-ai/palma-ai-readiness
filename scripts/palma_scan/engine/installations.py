"""Passive installed payload evidence. Versions are metadata, never execution or selection proof."""
from dataclasses import replace
from pathlib import Path, PureWindowsPath
import re
import stat

from .filesystem import ReadGap
from .identity import fingerprint
from .installation_paths import CLI_PACKAGES

VERSION_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?\Z")
CURSOR_VERSION_PATTERN = re.compile(r"[0-9]{4}\.[0-9]{2}\.[0-9]{2}-[a-f0-9]{7,40}\Z")


def version_label(value):
    return value if isinstance(value, str) and len(value) <= 100 and VERSION_PATTERN.fullmatch(value) else None


def contained_payload(root, value, *, basename=False):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ReadGap("unknown_schema", "unsupported")
    path = Path(value)
    if (path.is_absolute() or PureWindowsPath(value).drive or value.startswith(("/", "\\"))
            or ".." in value.replace("\\", "/").split("/")
            or (basename and ("/" in value or "\\" in value))):
        raise ReadGap("outside_scope")
    return root / path


def payload_candidate(candidate, path):
    return replace(candidate, path=path, format="executable", role="installed-payload",
                   location=candidate.location + "/payload")


def record_payload(builder, candidate, *, version=None, metadata_source=None, windows=False, script=False):
    source = builder.source(candidate)
    try:
        info = builder.files.info(candidate.path)
        if not stat.S_ISREG(info.st_mode) or not (windows or script or info.st_mode & 0o111):
            raise ReadGap("unknown_schema", "unsupported")
        builder.file_metadata(candidate, source, info)
        builder.ensure_client(candidate, metadata_source or source, installed=True, version=version)
    except ReadGap as error:
        source.update(status=error.status, reason=error.reason)


def collect_package(builder, candidate):
    source, data = builder.document(candidate)
    if data is None:
        return
    identity = CLI_PACKAGES.get(data.get("name")) if isinstance(data.get("name"), str) else None
    if identity is None or identity[0] != candidate.family:
        source.update(status="unsupported", reason="unknown_schema")
        return
    entry = data.get("bin")
    entry = entry.get(identity[1]) if isinstance(entry, dict) else entry
    try:
        path = contained_payload(candidate.path.parent, entry)
        record_payload(builder, payload_candidate(candidate, path), version=version_label(data.get("version")),
                       metadata_source=source, script=True)
    except ReadGap as error:
        builder.gap(candidate, error.reason, error.status)


def collect_editor(builder, candidate):
    source, data = builder.document(candidate)
    if data is None:
        return
    names = {"vscode": {"code", "code-insiders", "code - insiders"}, "cursor": {"cursor"}}
    name = data.get("name")
    if not isinstance(name, str) or name.lower() not in names.get(candidate.family, set()):
        source.update(status="unsupported", reason="unknown_schema")
        return
    windows = candidate.role.endswith("windows")
    binary = "Cursor.exe" if candidate.family == "cursor" else "Code.exe" if windows else "code"
    if candidate.family == "vscode" and "insiders" in candidate.path.parents[2].name.lower():
        binary = "Code - Insiders.exe" if windows else "code-insiders"
    path = candidate.path.parents[2] / binary
    record_payload(builder, payload_candidate(candidate, path), version=version_label(data.get("version")),
                   metadata_source=source, windows=windows)


def collect_versions(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return
    for path in children:
        label = path.name.removesuffix(".exe")
        version = version_label(label)
        if version is None or (candidate.role == "installed-cursor-versions" and not CURSOR_VERSION_PATTERN.fullmatch(label)):
            continue
        context = "installation:" + fingerprint(str(path))
        child = replace(candidate, context=context, path=path, format="executable", role="installed-payload",
                        location=candidate.location + "/version-" + version)
        if candidate.role == "installed-cursor-versions":
            child = replace(child, path=path / "cursor-agent")
        record_payload(builder, child, version=version, windows=candidate.role.endswith("windows"))


def collect_installation(builder, candidate):
    from .installation_apps import collect_applications, collect_desktop_versions
    from .installation_codex import collect_codex_releases
    from .installation_windows import collect_windows_msix
    from .windows_editors import collect_windows_editor
    if candidate.role == "installed-apps":
        collect_applications(builder, candidate)
    elif candidate.role == "installed-desktop-versions":
        collect_desktop_versions(builder, candidate)
    elif candidate.role == "installed-codex-releases":
        collect_codex_releases(builder, candidate)
    elif candidate.role == "installed-windows-msix":
        collect_windows_msix(builder, candidate)
    elif candidate.role == "installed-windows-editor":
        collect_windows_editor(builder, candidate)
    elif candidate.role in {"installed-versions", "installed-versions-windows", "installed-cursor-versions"}:
        collect_versions(builder, candidate)
    elif candidate.role == "installed-package":
        collect_package(builder, candidate)
    elif candidate.role.startswith("installed-editor-"):
        collect_editor(builder, candidate)
    elif candidate.role.startswith("installed-binary"):
        record_payload(builder, candidate, windows=candidate.role.endswith("windows"))
