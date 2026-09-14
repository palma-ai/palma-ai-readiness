"""Compare conservative provenance with Git on temporary repositories only."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from palma_scan.baseline import _version_controlled
from palma_scan.engine.collection import CollectOptions
from palma_scan.engine.filesystem import Budget, SafeFiles


@unittest.skipUnless(shutil.which("git"), "Git is used only as a test oracle")
class GitProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        template = self.home / "empty-template"
        template.mkdir()
        self.git("init", "--quiet", "--template=" + str(template))
        self.skill = self.repo / ".claude/skills/review/SKILL.md"
        self.skill.parent.mkdir(parents=True)
        self.skill.write_text("Fixture skill.")

    def git(self, *args):
        return subprocess.run([shutil.which("git"), "-C", str(self.repo), *args],
                              env=self.env, capture_output=True, check=True)

    def controlled(self, path=None):
        files = SafeFiles([self.home], Budget(CollectOptions(home=self.home), time.monotonic()))
        return _version_controlled(path or self.skill, self.home, files, {})

    def test_fake_or_dangling_repository_markers_never_lower_severity(self):
        shutil.rmtree(self.repo / ".git")
        (self.repo / ".git").mkdir()
        (self.repo / ".git/HEAD").write_text("ref: refs/heads/main\n")
        self.assertFalse(self.controlled())
        shutil.rmtree(self.repo / ".git")
        (self.repo / ".git").write_text("gitdir: ../does-not-exist\n")
        self.assertFalse(self.controlled())

    def test_repository_ignore_rules_agree_with_git(self):
        patterns = ("**/.claude/**", "/.claude/**/SKILL.md", "SKILL.md/", ".claude/*\n!.claude/skills/", "*.md",
                    ".claude/\n!.claude/skills/review/SKILL.md", "/.claude/skills/*/SKILL.md", "unrelated/")
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                (self.repo / ".gitignore").write_text(pattern + "\n")
                ignored = subprocess.run([shutil.which("git"), "-C", str(self.repo), "check-ignore", "-q", "--no-index", str(self.skill)], env=self.env).returncode
                self.assertIn(ignored, (0, 1))
                self.assertEqual(self.controlled(), ignored == 1)

    def test_nested_ignore_files_and_repository_excludes_are_applied(self):
        self.assertTrue(self.controlled())
        nested = self.skill.parent / ".gitignore"
        nested.write_text("SKILL.md\n")
        self.assertFalse(self.controlled())
        nested.unlink()
        (self.repo / ".git/info").mkdir()
        (self.repo / ".git/info/exclude").write_text("**/SKILL.md\n")
        self.assertFalse(self.controlled())

    def test_case_insensitive_repository_ignores_do_not_lower_severity(self):
        self.git("config", "core.ignoreCase", "true")
        (self.repo / ".gitignore").write_text(".CLAUDE/\n")
        self.git("check-ignore", "-q", "--no-index", str(self.skill))
        self.assertFalse(self.controlled())

    def test_negated_bracket_patterns_follow_git_semantics(self):
        self.git("config", "core.ignoreCase", "false")
        (self.repo / ".gitignore").write_text("[^a]KILL.md\n")
        self.git("check-ignore", "-q", "--no-index", str(self.skill))
        self.assertFalse(self.controlled())

    def test_valid_dotted_and_nested_branch_names_keep_repository_eligibility(self):
        for branch in ("release/1.0", "feature/alpha+beta", "team/branch_name"):
            with self.subTest(branch=branch):
                self.git("symbolic-ref", "HEAD", "refs/heads/" + branch)
                self.git("rev-parse", "--is-inside-work-tree")
                self.assertTrue(self.controlled())

    def test_linked_worktree_requires_existing_metadata_and_common_repository(self):
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test", "-c", "commit.gpgsign=false",
                 "-c", "core.hooksPath=" + os.devnull, "commit", "--allow-empty", "-qm", "Fixture")
        worktree = self.home / "linked"
        self.git("-c", "core.hooksPath=" + os.devnull, "worktree", "add", "-qb", "fixture", str(worktree))
        skill = worktree / ".claude/skills/review/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("Fixture skill.")
        self.assertTrue(self.controlled(skill))
        (self.repo / ".git/worktrees/linked/HEAD").unlink()
        self.assertFalse(self.controlled(skill))
