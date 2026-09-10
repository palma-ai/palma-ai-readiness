"""Offline deterministic inventory of the current account's approved sources."""
from __future__ import annotations

import math
import os
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .adapters.artifacts import scan_agents, scan_skills
from .adapters.configs import collect_cached_settings, collect_config
from .adapters.discovery import codex_profile_configs, dropin_configs, profile_configs, search_workspaces
from .adapters.plugins import scan_plugins
from .adapters.registries import probe_registry
from .filesystem import Budget, ReadGap, SafeFiles
from .installation_paths import installation_roots
from .installations import collect_installation
from .observations import ReportBuilder
from .paths import Candidate, bounded_environment, workspace_candidates
from .redaction import Redactor


@dataclass
class CollectOptions:
    home: Path | str | None = None
    os_name: str | None = None
    environ: Mapping[str, str] | None = None
    workspaces: Sequence[Path | str] = field(default_factory=tuple)
    search_roots: Sequence[Path | str] = field(default_factory=tuple)
    discover_os_packages: bool = True
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_sources: int = 1000000
    max_observations: int = 2000000
    max_files: int = 100000
    max_seconds: float = 300
    max_manifests: int = 20000


def _validate_options(options):
    if not isinstance(options.discover_os_packages, bool):
        raise ValueError("invalid OS package discovery option")
    for key in ("max_file_bytes", "max_total_bytes", "max_sources", "max_observations", "max_files"):
        value = getattr(options, key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError("invalid collection limit")
    if options.max_sources < 2:
        raise ValueError("invalid report limit")
    if not isinstance(options.max_seconds, (int, float)) or not math.isfinite(options.max_seconds) or options.max_seconds <= 0:
        raise ValueError("invalid time limit")


HOST_OS = {"darwin": "macos", "win32": "windows", "linux": "linux"}


def _context(options):
    home = Path(options.home).expanduser().absolute() if options.home is not None else Path.home()
    name = options.os_name or HOST_OS.get(sys.platform)
    if name not in {"macos", "windows", "linux"}:
        raise ValueError("unsupported operating system")
    environ = dict(os.environ if options.environ is None else options.environ)
    workspaces = list(dict.fromkeys(Path(path).expanduser().absolute() for path in options.workspaces))
    searches = list(dict.fromkeys(Path(path).expanduser().absolute() for path in options.search_roots))
    if home.parent == home or ".." in home.parts:
        raise ValueError("unsafe home root")
    for root in [*workspaces, *searches]:
        if root.parent == root or ".." in root.parts or (root != home and home.is_relative_to(root)):
            raise ValueError("collection root includes unrelated accounts")
    return home, name, environ, workspaces, searches


class Collection:
    def __init__(self, options, namespace, candidates):
        _validate_options(options)
        self.options = options
        self.home, self.os_name, self.environ, self.workspaces, self.searches = _context(options)
        self.environ, self.root_gaps = bounded_environment(self.environ, self.os_name, self.home)
        self.pending = list(candidates)
        roots = [self.home, *self.workspaces, *self.searches]
        roots.extend(installation_roots(self.pending))
        roots.extend(candidate.path for candidate in self.pending if candidate.format == "directory")
        exact_files = [candidate.path for candidate in self.pending if candidate.format != "directory"]
        self.files = SafeFiles(roots, Budget(options, time.monotonic()), exact_files)
        self.builder = ReportBuilder(self.files, Redactor(), options, namespace)
        self.processed = set()
        self.initial_workspaces = set(self.workspaces)

    def add_workspace(self, workspace):
        if not workspace.is_absolute() or ".." in workspace.parts:
            return False
        roots = [self.home, *self.workspaces, *self.searches]
        if not any(workspace.is_relative_to(root) for root in roots):
            return False
        try:
            self.files.approve(workspace)
        except ReadGap:
            return False
        if workspace not in self.workspaces:
            self.workspaces.append(workspace)
        return True

    def run(self):
        search_workspaces(self.builder, self.searches, self.add_workspace)
        self._process(self.pending)
        index = 0
        while index < len(self.workspaces):
            if self.workspaces[index] not in self.initial_workspaces:
                self._process(workspace_candidates(self.workspaces[index]))
            index += 1
        self._coverage()
        self.builder.finish()

    def _process(self, candidates):
        for candidate in candidates:
            key = (candidate.family, str(candidate.path), candidate.role, candidate.context)
            if key in self.processed:
                continue
            self.processed.add(key)
            try:
                # A large cache must not exhaust independent configuration sources.
                self.files.budget = Budget(self.options, time.monotonic())
                self.builder.manifests_seen = 0
                self._candidate(candidate)
            except ReadGap as error:
                self.builder.gap(candidate, error.reason, error.status)
                if error.reason in {"count_limit", "time_limit"}:
                    self.builder.limit_reason = error.reason
                    continue

    def _candidate(self, candidate):
        handlers = {"skills": scan_skills, "agents": scan_agents, "plugins": scan_plugins,
                    "registry-probe": probe_registry}
        if candidate.role in handlers:
            handlers[candidate.role](self.builder, candidate)
        elif candidate.role.startswith("installed-"):
            collect_installation(self.builder, candidate)
        elif candidate.role == "profiles":
            self._process(profile_configs(self.builder, candidate))
        elif candidate.role == "codex-profiles":
            self._process(codex_profile_configs(self.builder, candidate))
        elif candidate.role == "dropins":
            self._process(dropin_configs(self.builder, candidate))
        elif candidate.role == "installation":
            self._installation(candidate)
        else:
            source, data = self.builder.document(candidate)
            if data is not None:
                if candidate.role == "settings-cache":
                    collect_cached_settings(self.builder, candidate, source, data)
                else:
                    collect_config(self.builder, candidate, source, data, self.add_workspace)

    def _installation(self, candidate):
        source = self.builder.source(candidate)
        try:
            info = self.files.info(candidate.path)
            executable = self.os_name == "windows" or bool(info.st_mode & 0o111)
            if not stat.S_ISREG(info.st_mode) or not executable:
                raise ReadGap("unknown_schema", "unsupported")
            self.builder.file_metadata(candidate, source, info)
            self.builder.ensure_client(candidate, source, installed=True)
        except ReadGap as error:
            source.update(status=error.status, reason=error.reason)

    def _coverage(self):
        for variable in self.root_gaps:
            candidate = Candidate("unknown", "user", self.home / ".palma/scope" / variable, "scope:environment/" + variable)
            self.builder.gap(candidate, "outside_scope")


def collect_inventory(options: CollectOptions, namespace, candidates):
    """Return the in-memory original adapter collection, never write state."""
    collection = Collection(options, namespace, candidates)
    collection.run()
    return collection
