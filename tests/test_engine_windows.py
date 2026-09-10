"""Modeled MSIX contracts; only a native Windows run validates the Win32 ABI."""
import ctypes
import importlib
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

def file_symlink(test, path, target):
    try:
        path.symlink_to(target)
    except (OSError, NotImplementedError):
        test.skipTest("Symlinks unavailable on this test host")
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.engine.collection import CollectOptions
from palma_scan.engine.filesystem import Budget, ReadGap, SafeFiles
from palma_scan.engine.observations import ReportBuilder
from palma_scan.engine.redaction import Redactor

FAMILY = "Claude_pzs8sxrjxfjjc"
FULL_NAME = "Claude_1.24012.0.0_x64__pzs8sxrjxfjjc"
PUBLISHER = ('CN="Anthropic, PBC", O="Anthropic, PBC", L=San Francisco, S=California, C=US, '
             'SERIALNUMBER=4860621, OID.2.5.4.15=Private Organization, '
             'OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US')


def uint_value(pointer, value):
    ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0] = value


class PackageApi:
    def __init__(self, root):
        self.root, self.families, self.path_queries = root, [], []
        self.names = [FULL_NAME]
        self.error = None
        self.oversized = False

    def GetPackagesByPackageFamily(self, family, count, names, length, buffer):
        self.families.append(family)
        if self.error is not None:
            return self.error
        uint_value(count, 100_000 if self.oversized else len(self.names))
        uint_value(length, sum(len(value) + 1 for value in self.names))
        if names is None:
            return 122 if self.names else 0
        for index, value in enumerate(self.names):
            names[index] = value
        return 0

    def GetPackagePathByFullName(self, full_name, length, buffer):
        self.path_queries.append(full_name)
        if getattr(self, "path_error", None) is not None:
            return self.path_error
        uint_value(length, len(str(self.root)) + 1)
        if buffer is None:
            return 122
        buffer.value = str(self.root)
        return 0


class WindowsInstallationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name).resolve()
        options = CollectOptions(home=self.home, environ={})
        self.builder = ReportBuilder(SafeFiles([self.home], Budget(options, time.monotonic())),
                                     Redactor(), options, ("local", "~"))

    def module(self, name):
        self.assertTrue((Path(__file__).parents[1] / "scripts/palma_scan/engine" / (name + ".py")).exists(),
                        "Windows package discovery has not been implemented")
        return importlib.import_module("palma_scan.engine." + name)

    def package(self, *, executable=r"app\Claude.exe", publisher=PUBLISHER, prefix=""):
        from xml.sax.saxutils import quoteattr
        root = self.home / ("package-" + str(len(list(self.home.iterdir()))))
        (root / "app").mkdir(parents=True)
        (root / "app/Claude.exe").write_bytes(b"x" * 4096)
        (root / "app/Claude.exe").chmod(0o600)
        xml = ('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
               '<Identity Name="Claude" Version="1.24012.0.0" Publisher=' + quoteattr(publisher) + '/>'
               '<Applications><Application Id="Claude" Executable=' + quoteattr(executable) + '/></Applications></Package>')
        (root / "AppxManifest.xml").write_text(prefix + xml, encoding="utf-8")
        return root

    def collect(self, root):
        module = self.module("installation_windows")
        with patch.object(module, "registered_packages", side_effect=lambda **kw:
                          [(FULL_NAME, root)] if kw.get("package_family", FAMILY) == FAMILY else []):
            candidates = module.windows_msix_candidates(self.home)
        candidates = [candidate for candidate in candidates if not candidate.query_status]
        self.assertEqual(len(candidates), 1)
        with patch("subprocess.Popen", side_effect=AssertionError("Do not launch Windows tools")):
            module.collect_windows_msix(self.builder, candidates[0])

    def clients(self):
        return [value for value in self.builder.observations.values() if value["kind"] == "client"]

    def test_native_query_targets_only_known_current_user_family_and_bounds_allocations(self):
        module = self.module("windows_packages")
        api = PackageApi(self.home)
        self.assertEqual(module.registered_packages(api=api), [(FULL_NAME, self.home)])
        self.assertEqual(set(api.families), {FAMILY})
        self.assertEqual(set(api.path_queries), {FULL_NAME})
        api.oversized = True
        with self.assertRaises(ReadGap) as failure:
            module.registered_packages(api=api)
        self.assertEqual(failure.exception.reason, "count_limit")

    def test_empty_package_family_is_absent_and_api_denial_is_explicit_without_error_details(self):
        provider = self.module("windows_packages")
        api = PackageApi(self.home)
        api.names = []
        self.assertEqual(provider.registered_packages(api=api), [])
        api.names = [FULL_NAME]
        api.error = 15700  # APPMODEL_ERROR_NO_PACKAGE on a real endpoint without the family
        self.assertEqual(provider.registered_packages(api=api), [])
        api.error = None
        api.path_error = 15700  # the package vanished between the two queries: absent, not unreadable
        self.assertEqual(provider.registered_packages(api=api), [])
        api.path_error = None
        api.error = 5
        with self.assertRaises(ReadGap) as failure:
            provider.registered_packages(api=api)
        self.assertEqual((failure.exception.reason, failure.exception.status), ("permission_denied", "unreadable"))
        module = self.module("installation_windows")
        with patch.object(module, "registered_packages", side_effect=failure.exception):
            candidates = module.windows_msix_candidates(self.home)
        module.collect_windows_msix(self.builder, candidates[0])
        self.assertEqual(self.clients(), [])
        self.assertTrue(any(source["reason"] == "permission_denied" for source in self.builder.sources.values()))

    def test_registered_msix_manifest_and_payload_prove_version_without_binary_reads(self):
        root = self.package()
        self.builder.options.max_file_bytes = 1024
        self.collect(root)
        self.assertEqual([(value["family"], value["version"], value["installationState"]) for value in self.clients()],
                         [("claude-desktop", "1.24012.0.0", "installed")])
        self.assertEqual(self.builder.files.budget.files_read, 1)
        self.assertLess(self.builder.files.budget.bytes_read, 1024)

    def test_msix_manifest_identity_escape_and_redirect_cannot_create_installed_evidence(self):
        for root in (self.package(publisher="CN=Imposter"), self.package(executable=r"..\outside\Claude.exe")):
            self.collect(root)
        root = self.package()
        (root / "app/Claude.exe").unlink()
        outside = self.home / "outside.exe"
        outside.write_bytes(b"never collect")
        file_symlink(self, root / "app/Claude.exe", outside)
        self.collect(root)
        self.assertEqual(self.clients(), [])
        self.assertEqual({value["reason"] for value in self.builder.sources.values()} - {"none"},
                         {"unknown_schema", "outside_scope", "symlink"})

    def test_msix_xml_declarations_and_malformed_documents_are_visible_gaps(self):
        root = self.package(prefix='<!DOCTYPE Package [<!ENTITY forbidden "expanded">]>')
        self.collect(root)
        root = self.package()
        (root / "AppxManifest.xml").write_text("<Package><Identity", encoding="utf-8")
        self.collect(root)
        self.assertEqual(self.clients(), [])
        self.assertTrue(all(value["reason"] == "parse_error" for value in self.builder.sources.values()))

    def test_scope_opt_out_never_queries_os_packages_and_unknown_identities_never_resolve_paths(self):
        module = self.module("installation_windows")
        with patch.object(module, "registered_packages", side_effect=AssertionError("scope excludes OS registrations")):
            candidates = module.windows_msix_candidates(self.home, discover_os_packages=False)
        module.collect_windows_msix(self.builder, candidates[0])
        self.assertTrue(any(source["reason"] == "outside_scope" for source in self.builder.sources.values()))
        api = PackageApi(self.home)
        api.names = ["Unrelated_1.0.0.0_x64__otherpublisher"]
        with self.assertRaises(ReadGap) as failure:
            self.module("windows_packages").registered_packages(api=api)
        self.assertEqual(failure.exception.reason, "unknown_schema")
        self.assertEqual(api.path_queries, [])

    def test_codex_store_identity_and_both_published_executable_names_are_discovered(self):
        module = self.module("installation_windows")
        from xml.sax.saxutils import quoteattr
        for index, binary in enumerate(("Codex.exe", "ChatGPT.exe")):
            root = self.home / binary
            (root / "app").mkdir(parents=True)
            (root / "app" / binary).write_bytes(b"never execute this Windows payload")
            version = "26.820." + str(9563 + index) + ".0"
            full_name = "OpenAI.Codex_" + version + "_x64__2p2nqsd0c76g0"
            xml = ('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">'
                   '<Identity Name="OpenAI.Codex" Version=' + quoteattr(version) +
                   ' Publisher="CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B"/>'
                   '<Applications><Application Id="App" Executable=' + quoteattr("app\\" + binary) + '/></Applications></Package>')
            (root / "AppxManifest.xml").write_text(xml, encoding="utf-8")
            with patch.object(module, "registered_packages", side_effect=lambda **kw:
                              [(full_name, root)] if kw.get("package_family") == "OpenAI.Codex_2p2nqsd0c76g0" else []):
                candidates = module.windows_msix_candidates(self.home)
            for candidate in candidates:
                module.collect_windows_msix(self.builder, candidate)
        self.assertEqual([(item["family"], item["version"]) for item in self.clients()],
                         [("codex", "26.820.9563.0"), ("codex", "26.820.9564.0")])
