"""Exercise public Bash acquisition with fictional local downloads, never a scan."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/palma-ai/palma-ai-readiness"
TAG = "build-42-" + "a" * 40


@unittest.skipIf(os.name == "nt" or not shutil.which("bash"), "Bash instructions run on macOS and Linux")
class DownloadInstructionTests(unittest.TestCase):
    def run_download(self, *, bad_checksum=False, existing_directory=False):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td)
            archive = folder / "palma-ai-readiness.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("palma-ai-readiness/scripts/run.sh",
                                 'printf "synthetic launcher ran" > "$PALMA_TEST_DOWNLOAD/launched"\n')
            digest = "0" * 64 if bad_checksum else hashlib.sha256(archive.read_bytes()).hexdigest()
            (folder / "palma-ai-readiness.zip.sha256").write_text(digest + "  palma-ai-readiness.zip\n")
            (folder / "bin").mkdir()
            fake_curl = folder / "bin/curl"
            fake_curl.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, sys
folder = pathlib.Path(os.environ["PALMA_TEST_DOWNLOAD"])
url = sys.argv[-1]
with (folder / "requests").open("a") as stream:
    stream.write(json.dumps(url) + "\\n")
repo = "https://github.com/palma-ai/palma-ai-readiness"
tag = "build-42-" + "a" * 40
if url == repo + "/releases/latest":
    print(repo + "/releases/tag/" + tag, end="")
elif url.startswith(repo + "/releases/download/" + tag + "/"):
    name = url.rsplit("/", 1)[1]
    if name not in ("palma-ai-readiness.zip", "palma-ai-readiness.zip.sha256"):
        raise SystemExit(4)
    destination = pathlib.Path(sys.argv[sys.argv.index("--output") + 1])
    destination.write_bytes((folder / name).read_bytes())
else:
    raise SystemExit(4)
''')
            fake_curl.chmod(0o755)
            if existing_directory:
                (folder / "install").mkdir()
            command = re.search(r"```bash\n(.*?)```", (ROOT / "references/commands.md").read_text(), re.S).group(1)
            # Keep the documented workflow while selecting a temporary destination.
            original = 'palma_directory="$HOME/palma-scan-$palma_tag"'
            self.assertIn(original, command)
            command = command.replace(original, 'palma_directory="$PALMA_TEST_DOWNLOAD/install"')
            environment = {**os.environ, "PALMA_TEST_DOWNLOAD": str(folder),
                           "PATH": str(folder / "bin") + os.pathsep + os.environ["PATH"]}
            result = subprocess.run(["bash", "-c", command], env=environment, cwd=folder,
                                    capture_output=True, text=True)
            requests = [json.loads(line) for line in (folder / "requests").read_text().splitlines()]
            return result, requests, (folder / "launched").exists(), (folder / "install/palma-ai-readiness").exists()

    def test_latest_is_resolved_once_and_both_assets_use_the_same_tag(self):
        result, requests, launched, extracted = self.run_download()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(requests, [REPOSITORY + "/releases/latest",
                                   REPOSITORY + "/releases/download/" + TAG + "/palma-ai-readiness.zip",
                                   REPOSITORY + "/releases/download/" + TAG + "/palma-ai-readiness.zip.sha256"])
        self.assertTrue(launched and extracted)

    def test_checksum_failure_prevents_extraction_and_launch(self):
        result, _, launched, extracted = self.run_download(bad_checksum=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(launched or extracted)

    def test_existing_destination_is_preserved_without_asset_downloads(self):
        result, requests, launched, extracted = self.run_download(existing_directory=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(requests, [REPOSITORY + "/releases/latest"])
        self.assertFalse(launched or extracted)


if __name__ == "__main__":
    unittest.main()
