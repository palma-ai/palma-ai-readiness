#!/usr/bin/env python3
"""Publish a validated main-branch build; development automation, never shipped."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import urllib.error
import urllib.request
import zipfile

REPOSITORY = "palma-ai/palma-ai-readiness"
ARCHIVE = "palma-ai-readiness.zip"
TAG = re.compile(r"build-([1-9][0-9]*)-([0-9a-f]{40})")


def verified_assets(archive, commit):
    """Check the checksum, complete manifest, safe ZIP names and source identity."""
    if archive.name != ARCHIVE:
        raise ValueError(f"Expected {ARCHIVE}")
    data = archive.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    checksum = Path(str(archive) + ".sha256").read_bytes()
    if checksum != f"{digest}  {ARCHIVE}\n".encode("ascii"):
        raise ValueError("The archive checksum does not match")
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(set(names)) != len(names):
            raise ValueError("Duplicate ZIP entries")
        contents = {}
        for name in names:
            path = PurePosixPath(name)
            mode = package.getinfo(name).external_attr >> 16
            if (not name.startswith("palma-ai-readiness/") or ".." in path.parts
                    or "\\" in name or ":" in name or path.is_absolute() or name.endswith("/")
                    or name != path.as_posix() or mode & 0o170000 not in (0, 0o100000)):
                raise ValueError("Unexpected ZIP path")
            contents[name.removeprefix("palma-ai-readiness/")] = package.read(name)
        manifest = contents.pop("MANIFEST.sha256").decode("ascii")
        expected = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                           for name, data in sorted(contents.items()))
        if manifest != expected:
            raise ValueError("The release manifest does not match")
        if json.loads(contents["BUILD-INFO.json"]) != {"formatVersion": 1, "sourceCommit": commit}:
            raise ValueError("The release source commit does not match")
    return {ARCHIVE: data, ARCHIVE + ".sha256": checksum}


class GitHub:
    def __init__(self, token):
        self.token = token

    def request(self, method, path, *, payload=None, data=None, name=None, missing_ok=False):
        host = "https://uploads.github.com" if name else "https://api.github.com"
        url = f"{host}/repos/{REPOSITORY}/{path}"
        if name:
            url += "?name=" + name  # Fixed asset names contain only URL-safe characters.
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2026-03-10",
                   "User-Agent": "palma-release-automation"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif data is not None:
            headers["Content-Type"] = "application/octet-stream"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            raise RuntimeError(f"GitHub {method} {path} failed with HTTP {error.code}") from None


def is_newer(tag, latest):
    if latest is None:
        return True
    previous = TAG.fullmatch(latest.get("tag_name", ""))
    if not previous:
        raise ValueError("Latest release has an unmanaged tag; review it before automatic promotion")
    return int(TAG.fullmatch(tag).group(1)) >= int(previous.group(1))


def verified_tag(api, tag, commit):
    """Create a missing ref or verify its actual target, including annotated tags."""
    ref = api.request("GET", f"git/ref/tags/{tag}", missing_ok=True)
    if ref is None:
        ref = api.request("POST", "git/refs", payload={"ref": f"refs/tags/{tag}", "sha": commit})
    if ref.get("ref") != f"refs/tags/{tag}":
        raise ValueError("Release tag does not match this source commit")
    target = ref.get("object", {})
    seen = set()
    for _ in range(8):
        sha = target.get("sha", "")
        if target.get("type") == "commit" and sha == commit:
            return
        if target.get("type") != "tag" or not re.fullmatch(r"[0-9a-f]{40}", sha) or sha in seen:
            break
        seen.add(sha)
        target = api.request("GET", f"git/tags/{sha}").get("object", {})
    raise ValueError("Release tag does not match this source commit")


def publish(api, assets, commit, run_number):
    """Resume draft uploads, preserve published assets and prevent latest rollback."""
    tag = f"build-{run_number}-{commit}"
    # target_commitish is ignored by GitHub when a tag already exists.
    verified_tag(api, tag, commit)
    release = api.request("GET", f"releases/tags/{tag}", missing_ok=True)
    if release is None:
        release = api.request("POST", "releases", payload={
            "tag_name": tag, "target_commitish": commit,
            "name": f"Palma AI access scan · build {run_number}",
            "body": f"Standalone skill for source commit `{commit}`.\n\n"
                    "Validated on Windows, macOS and Linux with Python 3.11 and 3.14. "
                    "Download the skill ZIP and matching SHA-256 file below. "
                    "Automatic source-code archives are for development.\n",
            "draft": True, "prerelease": False, "make_latest": "false"})
    if release.get("target_commitish") != commit or release.get("prerelease"):
        raise ValueError("Existing release does not match this source commit")
    existing = {item["name"]: item for item in release.get("assets", [])}
    if set(existing) - set(assets):
        raise ValueError("Existing release contains unexpected assets")
    for name, data in assets.items():
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if name in existing:
            if existing[name].get("digest") != digest or existing[name].get("state") != "uploaded":
                raise ValueError("Existing asset differs; published files are never replaced")
        elif release["draft"]:
            uploaded = api.request("POST", f"releases/{release['id']}/assets", data=data, name=name)
            if uploaded.get("digest") != digest or uploaded.get("state") != "uploaded":
                raise ValueError("Uploaded asset digest does not match")
        else:
            raise ValueError("Published release is missing an asset; files are never replaced")
    latest = api.request("GET", "releases/latest", missing_ok=True)
    promote = is_newer(tag, latest)
    if release["draft"] or promote:
        api.request("PATCH", f"releases/{release['id']}",
                    payload={"draft": False, "make_latest": "true" if promote else "false"})
    print(f"Published https://github.com/{REPOSITORY}/releases/tag/{tag}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--run-number", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("Use a full lowercase 40-character source commit SHA")
    if not re.fullmatch(r"[1-9][0-9]*", args.run_number):
        parser.error("Use the positive GitHub workflow run number")
    token = os.environ.get("PALMA_GITHUB_TOKEN")
    if not token:
        parser.error("PALMA_GITHUB_TOKEN is required for publication")
    try:
        assets = verified_assets(args.archive, args.source_commit)
        publish(GitHub(token), assets, args.source_commit, int(args.run_number))
    except (OSError, ValueError, KeyError, RuntimeError, zipfile.BadZipFile) as error:
        parser.exit(2, f"Release publication stopped: {error}\n")


if __name__ == "__main__":
    main()
