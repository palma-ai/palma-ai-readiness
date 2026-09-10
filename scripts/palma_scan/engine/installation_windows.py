"""Known AI desktop MSIX metadata, scoped to exact registered package directories."""
from dataclasses import dataclass
from pathlib import PureWindowsPath
import xml.etree.ElementTree as ET

from .filesystem import ReadGap
from .identity import fingerprint
from .installations import contained_payload, payload_candidate, record_payload
from .paths import Candidate
from .windows_packages import registered_packages
from .windows_products import CLAUDE_FAMILY, FULL_NAMES, PRODUCTS

NAMESPACE = {"p": "http://schemas.microsoft.com/appx/manifest/foundation/windows10"}


@dataclass(frozen=True)
class MsixCandidate(Candidate):
    package_full_name: str = ""
    query_status: str = ""
    query_reason: str = ""


def query_status(home, status, reason, package_family):
    family = PRODUCTS[package_family]["family"]
    return MsixCandidate(family, "installation", home / ".palma-scan-discovery/windows-packages" / family,
                         "installation:windows-msix/current-user-registration/" + family, "unknown", "installed-windows-msix",
                         "installation:windows-msix/" + family, "desktop", query_status=status, query_reason=reason)


def windows_msix_candidates(home, *, discover_os_packages=True):
    return [candidate for family in PRODUCTS
            for candidate in family_candidates(home, family, discover_os_packages)]


def family_candidates(home, package_family, discover_os_packages):
    if not discover_os_packages:
        return [query_status(home, "skipped", "outside_scope", package_family)]
    try:
        packages = registered_packages(package_family=package_family)
    except ReadGap as error:
        return [query_status(home, error.status, error.reason, package_family)]
    if not packages:
        return [query_status(home, "absent", "not_found", package_family)]
    return [MsixCandidate(PRODUCTS[package_family]["family"], "installation", root / "AppxManifest.xml",
                          "installation:windows-msix/package-" + fingerprint(str(root))[:16],
                          "unknown", "installed-windows-msix", "installation:" + fingerprint(str(root)),
                          "desktop", package_full_name=name) for name, root in packages]


def manifest_metadata(raw, package_full_name):
    try:
        encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        text = raw.decode(encoding)
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError("unsupported XML declaration")
        root = ET.fromstring(text)
        if len(list(root.iter())) > 1000:
            raise ValueError("XML structure limit")
    except (ValueError, UnicodeError, ET.ParseError):
        raise ReadGap("parse_error", "invalid") from None
    identity = root.find("p:Identity", NAMESPACE)
    matched = [(family, pattern.fullmatch(package_full_name)) for family, pattern in FULL_NAMES.items()]
    package_family, match = next(((family, match) for family, match in matched if match), (CLAUDE_FAMILY, None))
    rule = PRODUCTS[package_family]
    if (identity is None or match is None or identity.get("Name") != rule["name"]
            or identity.get("Publisher") != rule["publisher"] or identity.get("Version") != match[1]):
        raise ReadGap("unknown_schema", "unsupported")
    applications = [app for app in root.findall("p:Applications/p:Application", NAMESPACE) if app.get("Id") == rule["app_id"]]
    if len(applications) != 1:
        raise ReadGap("unknown_schema", "unsupported")
    return match[1], applications[0].get("Executable"), rule["binaries"]


def collect_windows_msix(builder, candidate):
    if candidate.query_status:
        builder.source(candidate).update(status=candidate.query_status, reason=candidate.query_reason)
        return
    source, raw = builder.read(candidate)
    if raw is None:
        return
    try:
        version, executable, binaries = manifest_metadata(raw, candidate.package_full_name)
        # Convert the manifest's Windows separators for modeled fixtures too.
        relative = executable.replace("\\", "/") if isinstance(executable, str) else executable
        path = contained_payload(candidate.path.parent, relative)
        if PureWindowsPath(executable).name.lower() not in binaries:
            raise ReadGap("unknown_schema", "unsupported")
        record_payload(builder, payload_candidate(candidate, path), version=version,
                       metadata_source=source, windows=True)
    except ReadGap as error:
        source.update(status=error.status, reason=error.reason)
