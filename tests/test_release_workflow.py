"""Public release workflow permissions and platform gates stay explicit."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from palma_scan._vendor import yaml


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text())

    def test_only_successful_main_pushes_can_reach_the_write_token(self):
        workflow = self.workflow
        self.assertEqual(set(workflow["on"]), {"push", "pull_request"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        release = workflow["jobs"]["release"]
        self.assertEqual(release["permissions"], {"contents": "write"})
        self.assertEqual(set(release["needs"]), {"test", "build"})
        for required in ("github.event_name == 'push'", "github.ref == 'refs/heads/main'",
                         "github.repository == 'palma-ai/palma-ai-readiness'"):
            self.assertIn(required, release["if"])
        self.assertEqual(release["concurrency"], {"group": "palma-public-release", "queue": "max", "cancel-in-progress": False})
        for name, job in workflow["jobs"].items():
            if name != "release":
                self.assertNotIn("permissions", job)
                self.assertNotIn("github.token", str(job))
                self.assertNotIn("secrets.", str(job))
            for step in job["steps"]:
                if "uses" in step:
                    self.assertRegex(step["uses"], r"^actions/[a-z-]+@[0-9a-f]{40}$")
                    if step["uses"].startswith("actions/checkout@"):
                        self.assertIs(step["with"]["persist-credentials"], False)
                self.assertNotIn("${{", step.get("run", ""), "Pass GitHub context through environment values, not shell source")

    def test_all_native_platforms_gate_the_commit_artifact_and_release(self):
        jobs = self.workflow["jobs"]
        matrix = jobs["test"]["strategy"]["matrix"]
        self.assertEqual(set(matrix["os"]), {"ubuntu-24.04", "macos-15", "windows-2022"})
        self.assertEqual(set(matrix["python"]), {"3.11", "3.14"})
        self.assertEqual(matrix["exclude"], [{"os": "windows-2022", "python": "3.14"}], "one Windows job, on the minimum Python")
        self.assertFalse(jobs["test"]["strategy"]["fail-fast"])
        self.assertEqual(self.workflow["on"]["push"], {"branches": ["main"]}, "pull requests run once, main pushes release")
        self.assertEqual(jobs["build"]["needs"], "test")
        artifact = next(step for step in jobs["build"]["steps"] if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertEqual(set(artifact["with"]["path"].splitlines()),
                         {"dist/palma-ai-readiness.zip", "dist/palma-ai-readiness.zip.sha256"})
        self.assertEqual(artifact["with"]["if-no-files-found"], "error")
        self.assertIn("github.run_attempt", artifact["with"]["name"])
        download = next(step for step in jobs["release"]["steps"] if step.get("uses", "").startswith("actions/download-artifact@"))
        self.assertEqual(download["with"]["artifact-ids"], "${{ needs.build.outputs.artifact-id }}")


if __name__ == "__main__":
    unittest.main()
