"""Read only exact known AI editor installer keys, never enumerate installed software."""
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from .filesystem import ReadGap
from .identity import fingerprint
from .installations import payload_candidate, record_payload, version_label
from .paths import Candidate

UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall" + "\\"
# Product codes and scopes from the vendors' Microsoft winget installer manifests.
INSTALLERS = (
    ("kiro", "Kiro", "user", "{A2CA08B5-C756-463E-B13D-F051F4F11F0B}_is1"),
    ("windsurf", "Windsurf", "user", "{5A8B7D94-9B5F-4D1F-93FC-5609F7159349}_is1"),
    ("windsurf", "Windsurf", "machine", "{A71B58E9-CEFB-4424-8A1D-A0E49CF18EBB}_is1"),
    ("windsurf", "Windsurf", "user", "{1A69CEA0-8DA8-4B3E-950C-23FA9F850651}_is1"),
    ("windsurf", "Windsurf", "machine", "{9B0AE7D1-5CD0-43E6-B7B0-EE4B79723A25}_is1"),
)


@dataclass(frozen=True)
class EditorCandidate(Candidate):
    installed_version: str = ""
    query_status: str = ""
    query_reason: str = ""


def load_registry():
    try:
        import winreg
        return winreg
    except ImportError:
        raise ReadGap("unknown_schema", "unsupported") from None


def status_candidate(home, installer, status, reason):
    family, _, scope, key = installer
    label = "windows-installer/" + family + "/" + scope + "/" + fingerprint(key)[:12]
    return EditorCandidate(family, "installation", home / ".palma-scan-discovery" / label,
                           "installation:" + label, "unknown", "installed-windows-editor",
                           "installation:" + label, "ide", query_status=status, query_reason=reason)


def install_metadata(registry, key, name):
    values = {}
    for field in ("DisplayName", "DisplayVersion", "InstallLocation"):
        value, kind = registry.QueryValueEx(key, field)
        if kind != registry.REG_SZ or not isinstance(value, str) or len(value) > 32768 or "\x00" in value:
            raise ReadGap("unknown_schema", "unsupported")
        values[field] = value
    if values["DisplayName"] not in {name, name + " (User)"}:
        raise ReadGap("unknown_schema", "unsupported")
    version = version_label(values["DisplayVersion"])
    if version is None:
        raise ReadGap("unknown_schema", "unsupported")
    location = values["InstallLocation"]
    root = Path(location)
    if (location.startswith(("\\\\", "//")) or not root.is_absolute() or root.parent == root
            or ".." in root.parts or ".." in PureWindowsPath(location).parts):
        raise ReadGap("outside_scope")
    return root, version


def installer_candidate(home, registry, installer):
    family, name, scope, key_name = installer
    hive = registry.HKEY_CURRENT_USER if scope == "user" else registry.HKEY_LOCAL_MACHINE
    try:
        key = registry.OpenKey(hive, UNINSTALL + key_name, 0, registry.KEY_READ | registry.KEY_WOW64_64KEY)
    except FileNotFoundError:
        return status_candidate(home, installer, "absent", "not_found")
    with key:
        try:
            root, version = install_metadata(registry, key, name)
        except FileNotFoundError:
            raise ReadGap("unknown_schema", "unsupported") from None
    label = "windows-installer/" + family + "/" + scope + "/" + fingerprint(str(root))[:16]
    return EditorCandidate(family, "installation", root / (name + ".exe"), "installation:" + label,
                           "unknown", "installed-windows-editor", "installation:" + fingerprint(str(root)),
                           "ide", installed_version=version)


def registered_editors(home):
    registry = load_registry()
    result = []
    for installer in INSTALLERS:
        try:
            result.append(installer_candidate(home, registry, installer))
        except ReadGap as error:
            result.append(status_candidate(home, installer, error.status, error.reason))
        except OSError as error:
            reason = "permission_denied" if isinstance(error, PermissionError) else "io_error"
            result.append(status_candidate(home, installer, "unreadable", reason))
    return result


def windows_editor_candidates(home, *, discover_os_packages=True):
    if not discover_os_packages:
        return [status_candidate(home, installer, "skipped", "outside_scope") for installer in INSTALLERS]
    try:
        return registered_editors(home)
    except ReadGap as error:
        return [status_candidate(home, installer, error.status, error.reason) for installer in INSTALLERS]


def collect_windows_editor(builder, candidate):
    source = builder.source(candidate)
    if candidate.query_status:
        source.update(status=candidate.query_status, reason=candidate.query_reason)
        return
    record_payload(builder, payload_candidate(candidate, candidate.path), version=candidate.installed_version,
                   metadata_source=source, windows=True)
