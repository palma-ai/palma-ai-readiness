"""Offline checks for release identity, resume behavior, and monotonic latest."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_release", ROOT / "scripts/publish_release.py")
publication = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publication)
COMMIT = "a" * 40
ASSETS = {"palma-ai-readiness.zip": b"package", "palma-ai-readiness.zip.sha256": b"checksum"}


class FakeGitHub:
    def __init__(self, release=None, latest=None, tag=None, tag_objects=None):
        self.release = release
        self.latest = latest
        self.tag = tag if tag is not None else ({"ref": "refs/tags/build-12-" + COMMIT,
                                                "object": {"type": "commit", "sha": COMMIT}} if release else None)
        self.tag_objects = tag_objects or {}
        self.calls = []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if method == "GET":
            if path.startswith("git/ref/tags/"):
                return self.tag
            if path.startswith("git/tags/"):
                return self.tag_objects[path.removeprefix("git/tags/")]
            return self.latest if path == "releases/latest" else self.release
        if path == "git/refs":
            self.tag = {"ref": kwargs["payload"]["ref"], "object": {"type": "commit", "sha": kwargs["payload"]["sha"]}}
            return self.tag
        if path == "releases":
            self.release = {"id": 1, "assets": [], **kwargs["payload"]}
            return self.release
        if method == "POST":
            asset = {"name": kwargs["name"], "state": "uploaded",
                     "digest": "sha256:" + hashlib.sha256(kwargs["data"]).hexdigest()}
            self.release["assets"].append(asset)
            return asset
        self.release.update(kwargs["payload"])
        return self.release


def stored_release(draft=False, assets=ASSETS):
    return {"id": 1, "draft": draft, "prerelease": False, "target_commitish": COMMIT,
            "assets": [{"name": name, "state": "uploaded", "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
                       for name, data in assets.items()]}


class PublicationTests(unittest.TestCase):
    def publish(self, api, run_number=12):
        with patch("sys.stdout", new=io.StringIO()):
            publication.publish(api, ASSETS, COMMIT, run_number)

    def test_uploads_a_draft_before_publishing_both_matching_assets(self):
        api = FakeGitHub()
        self.publish(api)
        creation = next(call for call in api.calls if call[:2] == ("POST", "releases"))
        self.assertTrue(creation[2]["payload"]["draft"])
        self.assertEqual(creation[2]["payload"]["make_latest"], "false")
        self.assertEqual(api.tag["object"], {"type": "commit", "sha": COMMIT})
        self.assertEqual([call[2]["name"] for call in api.calls if call[0] == "POST" and "name" in call[2]], list(ASSETS))
        self.assertEqual(api.calls[-1], ("PATCH", "releases/1", {"payload": {"draft": False, "make_latest": "true"}}))

    def test_an_older_successful_run_is_published_without_rolling_latest_back(self):
        api = FakeGitHub(latest={"tag_name": "build-13-" + "b" * 40})
        self.publish(api)
        self.assertEqual(api.calls[-1][2]["payload"], {"draft": False, "make_latest": "false"})

    def test_reruns_reuse_matching_published_assets_and_never_replace_them(self):
        api = FakeGitHub(stored_release(), {"tag_name": "build-13-" + "b" * 40})
        self.publish(api)
        self.assertTrue(all(call[0] == "GET" for call in api.calls))

    def test_a_matching_draft_resumes_only_missing_uploads(self):
        api = FakeGitHub(stored_release(draft=True, assets={"palma-ai-readiness.zip": ASSETS["palma-ai-readiness.zip"]}))
        self.publish(api)
        uploads = [call[2]["name"] for call in api.calls if call[0] == "POST"]
        self.assertEqual(uploads, ["palma-ai-readiness.zip.sha256"])

    def test_different_existing_bytes_or_commit_are_never_replaced(self):
        for change in ("digest", "commit", "unexpected", "missing"):
            with self.subTest(change=change):
                release = stored_release()
                if change == "digest":
                    release["assets"][0]["digest"] = "sha256:" + "0" * 64
                elif change == "commit":
                    release["target_commitish"] = "b" * 40
                elif change == "unexpected":
                    release["assets"].append({"name": "snapshot.json"})
                else:
                    release["assets"] = []
                api = FakeGitHub(release)
                with self.assertRaises(ValueError):
                    self.publish(api)
                self.assertTrue(all(call[0] == "GET" for call in api.calls))

    def test_latest_order_is_numeric_and_unmanaged_tags_require_review(self):
        self.assertTrue(publication.is_newer("build-100-" + COMMIT, {"tag_name": "build-99-" + COMMIT}))
        with self.assertRaises(ValueError):
            publication.is_newer("build-12-" + COMMIT, {"tag_name": "manual-release"})

    def test_existing_tag_must_resolve_to_the_validated_source_before_any_write(self):
        tag_name = "refs/tags/build-12-" + COMMIT
        for target in ("b" * 40, COMMIT):
            with self.subTest(target=target):
                api = FakeGitHub(stored_release(), tag={"ref": tag_name, "object": {"type": "tag", "sha": "c" * 40}},
                                 tag_objects={"c" * 40: {"object": {"type": "commit", "sha": target}}})
                if target == COMMIT:
                    self.publish(api)
                else:
                    with self.assertRaisesRegex(ValueError, "tag.*source commit"):
                        self.publish(api)
                    self.assertTrue(all(call[0] == "GET" for call in api.calls))
        api = FakeGitHub(tag={"ref": tag_name, "object": {"type": "commit", "sha": "b" * 40}})
        with self.assertRaisesRegex(ValueError, "tag.*source commit"):
            self.publish(api)
        self.assertTrue(all(call[0] == "GET" for call in api.calls))

    def test_tag_resolution_rejects_cycles_and_noncommit_objects(self):
        tag_name = "refs/tags/build-12-" + COMMIT
        for kind in ("tag", "tree"):
            with self.subTest(kind=kind):
                object_data = {"type": kind, "sha": "c" * 40}
                api = FakeGitHub(tag={"ref": tag_name, "object": object_data},
                                 tag_objects={"c" * 40: {"object": object_data}})
                with self.assertRaisesRegex(ValueError, "tag.*source commit"):
                    self.publish(api)
                self.assertTrue(all(call[0] == "GET" for call in api.calls))

    def test_archive_verification_checks_manifest_source_and_safe_paths(self):
        with tempfile.TemporaryDirectory() as td:
            archive = Path(td)/publication.ARCHIVE
            def write_package(extra=None, source=COMMIT, bad_manifest=False):
                files = {"BUILD-INFO.json": json.dumps({"formatVersion": 1, "sourceCommit": source}).encode(),
                         "SKILL.md": b"fictional skill"}
                if extra:
                    files[extra] = b"unwanted"
                manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(files.items()))
                files["MANIFEST.sha256"] = b"bad" if bad_manifest else manifest.encode()
                with zipfile.ZipFile(archive, "w") as package:
                    for name, data in files.items():
                        package.writestr("palma-ai-readiness/" + name, data)
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                Path(str(archive) + ".sha256").write_bytes(f"{digest}  {publication.ARCHIVE}\n".encode())
            write_package()
            self.assertEqual(set(publication.verified_assets(archive, COMMIT)), set(ASSETS))
            for options in ({"extra": "../outside"}, {"extra": "scripts\\escape.py"}, {"extra": "scripts//alias.py"},
                            {"extra": "scripts/stream.py:payload"},
                            {"source": "b" * 40}, {"bad_manifest": True}):
                with self.subTest(options=options):
                    write_package(**options)
                    with self.assertRaises(ValueError):
                        publication.verified_assets(archive, COMMIT)
            write_package()
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                publication.verified_assets(archive, COMMIT)


if __name__ == "__main__":
    unittest.main()
