"""Codex's registered standalone packages, independent of current/launcher redirects."""
from dataclasses import replace
import re

from .filesystem import ReadGap
from .identity import fingerprint
from .installations import contained_payload, payload_candidate, record_payload, version_label

RELEASE_LABEL = re.compile(r"[0-9][A-Za-z0-9_.+-]{0,199}\Z")
TARGET_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}\Z")


def collect_codex_releases(builder, candidate):
    _, children = builder.directory(candidate)
    if children is None:
        return
    for path in children:
        if not RELEASE_LABEL.fullmatch(path.name):
            continue
        child = replace(candidate, path=path / "codex-package.json", format="json",
                        role="installed-codex-package", context="installation:" + fingerprint(str(path)),
                        location=candidate.location + "/release-" + fingerprint(str(path))[:16])
        with builder.isolated(candidate):
            collect_codex_package(builder, child)


def collect_codex_package(builder, candidate):
    source, data = builder.document(candidate)
    if data is None:
        return
    version, target = version_label(data.get("version")), data.get("target")
    if (type(data.get("layoutVersion")) is not int or data["layoutVersion"] != 1
            or data.get("variant") != "codex" or version is None
            or not isinstance(target, str) or not TARGET_LABEL.fullmatch(target)
            or candidate.path.parent.name != version + "-" + target):
        source.update(status="unsupported", reason="unknown_schema")
        return
    try:
        path = contained_payload(candidate.path.parent, data.get("entrypoint"))
        windows = target.endswith("-windows-msvc")
        expected = "bin/codex.exe" if windows else "bin/codex"
        if data["entrypoint"] != expected:
            raise ReadGap("unknown_schema", "unsupported")
        record_payload(builder, payload_candidate(candidate, path), version=version,
                       metadata_source=source, windows=windows)
    except ReadGap as error:
        builder.gap(candidate, error.reason, error.status)
