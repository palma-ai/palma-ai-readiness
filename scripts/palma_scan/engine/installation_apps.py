"""One-level macOS application discovery with exact bundle identity and payload checks."""
from dataclasses import replace

from .filesystem import ReadGap
from .identity import fingerprint
from .installations import contained_payload, payload_candidate, record_payload, version_label

# Verified vendor metadata; helpers and URL handlers are intentionally not client identities.
BUNDLE_CLIENTS = {"com.openai.codex": ("codex", "desktop"),
                  "com.anthropic.claudefordesktop": ("claude-desktop", "desktop"),
                  "com.anthropic.claude-code": ("claude-code", "cli"),
                  "com.todesktop.230313mzl4w4u92": ("cursor", "ide"),
                  "com.microsoft.VSCode": ("vscode", "ide")}


def collect_bundle(builder, parent, path, *, known_family=False):
    label = fingerprint(str(path))[:16]
    candidate = replace(parent, path=path / "Contents/Info.plist", format="plist", role="installed-app-metadata",
                        context="installation:" + fingerprint(str(path)), location=parent.location + "/app-" + label)
    # The bundle identity lives inside Info.plist, so it must be read before the
    # allowlist can decide. The probe neither teaches the redactor nor caches the
    # document; an unknown bundle is not a census entry, so every source, gap and
    # fingerprint it registered is discarded again. Only a collection limit hit
    # during the probe survives, re-attached to the parent directory so budget
    # exhaustion stays visible without naming the bundle.
    try:
        known, source, data = builder.probe_document(candidate)
    except ReadGap as error:
        builder.gap(parent, error.reason, error.status)
        return
    identity = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    if not isinstance(identity, str) or identity not in BUNDLE_CLIENTS:
        if known_family and data is None:
            return  # a known client location that could not be read stays a visible gap
        for dropped in builder.discard_since(known):
            # Budget exhaustion is collection state and must stay visible; a per-file
            # size_limit on an unrelated bundle is not, and would name the bundle.
            if dropped.get("reason") in {"count_limit", "time_limit"}:
                builder.gap(parent, dropped["reason"], dropped["status"])
        return
    builder.adopt_document(source, data)
    family, variant = BUNDLE_CLIENTS[identity]
    candidate = replace(candidate, family=family, variant=variant)
    source["family"] = family
    try:
        executable = contained_payload(path / "Contents/MacOS", data.get("CFBundleExecutable"), basename=True)
        version = version_label(data.get("CFBundleShortVersionString")) or version_label(data.get("CFBundleVersion"))
        record_payload(builder, payload_candidate(candidate, executable), version=version, metadata_source=source)
    except ReadGap as error:
        builder.gap(candidate, error.reason, error.status)


def collect_applications(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return
    for path in children:
        if path.suffix.lower() == ".app":
            collect_bundle(builder, candidate, path)


def collect_desktop_versions(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return
    for path in children:
        if version_label(path.name):
            # Current observed Desktop layout; each bundle's own version is authoritative metadata.
            # The family is known a priori here, so an unreadable bundle stays a visible gap.
            collect_bundle(builder, candidate, path / "claude.app", known_family=True)
