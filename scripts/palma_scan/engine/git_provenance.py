"""Bounded repository metadata checks; never run Git or read its index or objects."""
import configparser
import fnmatch
from functools import lru_cache
import os
from pathlib import Path
import re
import stat

from .filesystem import ReadGap

MAX_RULES = 1000


def _text(path, files, optional=False):
    try:
        return files.read(path)[0].decode("utf-8")
    except ReadGap as error:
        if optional and error.reason == "not_found":
            return ""
        raise


def _metadata_path(base, value):
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise ValueError("unsupported Git metadata path")
    # Normalize relative worktree paths lexically; SafeFiles still rejects redirects
    # and any target outside the approved collection scope.
    return Path(os.path.abspath(base / value))


def _valid_head(head):
    if re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", head):
        return True
    if not head.startswith("ref: refs/"):
        return False
    ref = head[5:]
    if re.search(r"[\x00-\x20\x7f~^:?*\[\\]", ref) or ".." in ref or "@{" in ref or ref.endswith("."):
        return False
    return all(part and not part.startswith(".") and not part.endswith(".lock") for part in ref.split("/"))


def _repository(folder, files):
    marker = folder / ".git"
    try:
        info = files.info(marker)
    except ReadGap as error:
        if error.reason == "not_found":
            return None
        raise
    gitdir = marker
    if not stat.S_ISDIR(info.st_mode):
        declaration = _text(marker, files).strip()
        if not declaration.startswith("gitdir: "):
            raise ValueError("unsupported Git marker")
        gitdir = _metadata_path(folder, declaration[8:])
    head = _text(gitdir / "HEAD", files).strip()
    if not _valid_head(head):
        raise ValueError("unsupported Git HEAD")
    common = _text(gitdir / "commondir", files, optional=True).strip()
    common_dir = _metadata_path(gitdir, common) if common else gitdir
    if common:
        backlink = _metadata_path(gitdir, _text(gitdir / "gitdir", files).strip())
        if backlink != marker:
            raise ValueError("inconsistent worktree metadata")
    for name in ("objects", "refs"):
        if not stat.S_ISDIR(files.info(common_dir / name).st_mode):
            raise ValueError("incomplete Git repository")
    config = configparser.RawConfigParser(allow_no_value=True, interpolation=None,
                                         inline_comment_prefixes=("#", ";"))
    config.read_string(_text(common_dir / "config", files, optional=True))
    # Includes, worktree-specific configuration and a relocated worktree need a
    # full Git configuration resolver; they cannot justify a lower rating here.
    if any(section.lower().startswith(("include", "extensions")) for section in config.sections()):
        raise ValueError("unsupported Git configuration")
    core = next((section for section in config.sections() if section.lower() == "core"), None)
    ignore_case = False
    if core:
        if config.has_option(core, "worktree"):
            raise ValueError("relocated Git worktree")
        def boolean(key, default="false"):
            value = config.get(core, key, fallback=default)
            value = "true" if value is None else value.strip('"').lower()
            if value not in {"true", "yes", "on", "1", "false", "no", "off", "0", ""}:
                raise ValueError("unsupported Git boolean")
            return value in {"true", "yes", "on", "1"}
        if boolean("bare"):
            raise ValueError("bare repository")
        ignore_case = boolean("ignorecase")
    return common_dir, ignore_case


def _rules(path, files, cache, ignore_case):
    key = ("ignore", path, ignore_case)
    if key in cache:
        return cache[key]
    rules = []
    for line in _text(path, files, optional=True).splitlines():
        pattern = line.rstrip(" ")
        if not pattern or pattern.startswith("#"):
            continue
        # Unsupported syntax stays unknown, so it can never lower a skill's rating.
        if "\\" in pattern or "[:" in pattern or len(pattern) > 1024:
            raise ValueError("unsupported ignore pattern")
        negate = pattern.startswith("!")
        pattern = pattern.removeprefix("!")
        directory_only = pattern.endswith("/")
        anchored = "/" in pattern.rstrip("/")
        parts = pattern.strip("/").split("/")
        if not pattern or len(parts) > 64:
            raise ValueError("unsupported ignore pattern")
        compiled = tuple(None if part == "**" else re.compile(
            fnmatch.translate(part.replace("[^", "[!")), re.I | re.ASCII if ignore_case else 0) for part in parts)
        rules.append((negate, directory_only, anchored, compiled))
        if len(rules) > MAX_RULES:
            raise ValueError("ignore rule limit")
    cache[key] = rules
    return rules


def _matches(pattern, parts):
    @lru_cache(maxsize=None)
    def match(i, j):
        if i == len(pattern):
            return j == len(parts)
        if pattern[i] is None:
            # Trailing /** matches contents, not the directory itself.
            if i == len(pattern) - 1:
                return j < len(parts)
            return match(i + 1, j) or (j < len(parts) and match(i, j + 1))
        return j < len(parts) and bool(pattern[i].fullmatch(parts[j])) and match(i + 1, j + 1)
    return match(0, 0)


def _ignored(path, folder, repository, files, cache):
    common, ignore_case = repository
    parts = path.relative_to(folder).parts
    rules = [(0, rule) for rule in _rules(common / "info/exclude", files, cache, ignore_case)]
    for depth in range(len(parts)):
        directory = folder.joinpath(*parts[:depth])
        rules.extend((depth, rule) for rule in _rules(directory / ".gitignore", files, cache, ignore_case))
        if len(rules) > MAX_RULES:
            raise ValueError("ignore rule limit")
        excluded = False
        for base, (negate, directory_only, anchored, pattern) in rules:
            if directory_only and depth == len(parts) - 1:
                continue
            relative = parts[base:depth + 1] if anchored else (parts[depth],)
            if _matches(pattern, relative):
                excluded = not negate
        if excluded:
            return True  # Git cannot re-include children of an excluded directory.
    return False


def version_controlled(path, stop, files, cache):
    """Repository indicator, not proof of tracking, commits, review or global Git policy.

    Check repository structure and repository-local ignore files. Unknown metadata,
    unsupported ignore syntax or budget exhaustion never qualifies for a lower rating.
    Stop at the home: a dotfiles repository must not label all projects as reviewed.
    """
    try:
        for folder in list(path.parents)[:16]:
            if folder == stop or folder.parent == folder:
                return False
            key = ("repo", folder)
            if key not in cache:
                cache[key] = _repository(folder, files)
            if cache[key] is not None:
                return not _ignored(path, folder, cache[key], files, cache)
    except (ReadGap, ValueError, UnicodeError, configparser.Error):
        return False
    return False
