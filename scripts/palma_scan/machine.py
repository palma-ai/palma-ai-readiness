"""Machine discovery: filesystem metadata and fixed, read-only OS inventories.

Discovered executables, hooks, installers, and server commands are never run.
Physical paths/account metadata exist only in memory; saved discovery evidence
contains fixed labels, counters, and known client identities.
"""
from collections import deque
from datetime import datetime, timezone
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PureWindowsPath
import plistlib
import re
import stat
import subprocess
import sys
import time

DEFAULT_DIRECTORY_LIMIT = 500_000
DEFAULT_ENTRY_LIMIT = 5_000_000
DEFAULT_SECONDS = 1800
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_OS_OUTPUT_BYTES = 8 * 1024 * 1024

EXECUTABLES = {
    "codex": "codex", "claude": "claude-code", "claude-desktop": "claude-desktop",
    "cursor": "cursor", "cursor-agent": "cursor", "agent": "cursor",
    "gemini": "gemini-cli", "code": "vscode", "code-insiders": "vscode",
    "windsurf": "windsurf", "windsurf-next": "windsurf", "ollama": "ollama",
    "lm-studio": "lm-studio", "lm studio": "lm-studio", "lms": "lm-studio",
    "opencode": "opencode", "copilot": "copilot-cli", "aider": "aider",
    "kiro": "kiro", "kiro-cli": "kiro", "continue": "continue", "cn": "continue",
    "antigravity": "antigravity", "chatgpt": "chatgpt", "goose": "goose",
    "agy": "antigravity", "openclaw": "openclaw",
}
PROJECT_MARKERS = {".codex", ".claude", ".cursor", ".gemini", ".vscode", ".agents",
                   ".github", ".mcp.json", ".opencode", "opencode.json", "opencode.jsonc",
                   ".continue", ".roo", ".kilocode", ".kiro", ".aider.conf.yml", ".copilot", ".openclaw"}
PRUNE_NAMES = {".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
               "site-packages", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
               ".cache", "Cache", "Caches", "cache", "CachedData", "Code Cache",
               "GPUCache", "Service Worker", ".Trash", ".Trashes", "$RECYCLE.BIN",
               "System Volume Information", ".Spotlight-V100", ".fseventsd",
               ".DocumentRevisions-V100", "Backups.backupdb", ".timemachine",
               "com.apple.TimeMachine.localsnapshots", "FileHistory", "WindowsImageBackup",
               # Cloud-synced folders download online-only files when they are listed or read.
               "CloudStorage", "Mobile Documents"}
SF_DATALESS = 0x40000000
LOCAL_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "bcachefs",
            "overlay", "rootfs", "apfs", "hfs", "hfsplus", "ufs", "msdos", "vfat",
            "exfat", "ntfs", "ntfs3", "fuseblk", "jfs", "reiserfs", "squashfs"}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb3", "sshfs", "fuse.sshfs", "afpfs", "davfs", "9p"}
# Folders inside profile roots that are not a person's account.
NON_ACCOUNT_PROFILE_NAMES = {"Shared", "Public", "Default", "Default User", "All Users", "defaultuser0", "linuxbrew"}
NO_LOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/bin/false", "/usr/bin/false", "/bin/sync"}
# Folders owned by another person's account are not opened wherever they are: a relocated,
# mounted or linked home, a backup of one, or a folder they own elsewhere. Lower ids and
# nobody are system accounts, which own shared locations such as /opt and /Volumes.
PERSON_UID_MINIMUM = {"macos": 500, "linux": 1000}
NOBODY_UIDS = {65534, 4294967294}
# Fixed OS temporary roots: transient agent sessions and scratch copies, not projects.
# Explicit --workspace paths are still collected. Environment variables such as TMPDIR
# are deliberately not consulted, so they cannot hide a directory from discovery.
TEMPORARY_ROOTS = {"macos": ("/private/tmp", "/private/var/tmp", "/private/var/folders"),
                   "linux": ("/tmp", "/var/tmp")}
# This scanner's own folder: a development clone or extracted release is not user evidence.
SCANNER_ROOT = Path(__file__).resolve().parents[2]
AI_EXTENSION_NAME = re.compile(r"\b(?:ChatGPT|Claude|Copilot|Gemini|Ollama|Perplexity|Sider|Monica|Merlin|HARPA AI|MaxAI|AI assistant)\b", re.I)
EXTENSION_PERMISSIONS = {"debugger", "nativeMessaging", "tabs", "scripting", "cookies",
                         "downloads", "clipboardRead", "clipboardWrite", "webRequest"}


def _id(*items):
    return hashlib.sha256("\x1f".join(map(str, items)).encode()).hexdigest()[:16]


def _identity(path):
    """A directory entry's (device, inode), without following a final link; None if unknown."""
    try:
        info = Path(path).lstat()
    except (OSError, ValueError):
        return None
    return (info.st_dev, info.st_ino) if info.st_ino else None


def _open_unredirected(path, flags):
    """Open a path one component at a time from the filesystem root, following no link.

    A folder checked earlier and swapped for a link afterwards is refused, not followed.
    """
    path = Path(path)
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        return os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
    parts = path.relative_to(path.anchor).parts
    if not parts:
        return os.open(path, flags | os.O_NOFOLLOW)
    access = getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY)) | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, access)
    try:
        for part in parts[:-1]:
            child = os.open(part, access, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(parts[-1], flags | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def _regular_metadata(path, parser="json"):
    """Read only a selected bounded metadata document; never follow any link on its path."""
    path = Path(path)
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("redirected metadata")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA_BYTES:
        raise ValueError("unsupported metadata file")
    fd = _open_unredirected(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("metadata changed while opening")
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("metadata size limit")
    if parser == "bytes":
        return raw
    if parser == "plist":
        try:
            result = plistlib.loads(raw)
            _validate_metadata(result)
        except Exception as error:
            # plistlib raises ExpatError, AttributeError, LookupError or
            # IndexError for malformed documents; callers handle ValueError.
            raise ValueError("unsupported metadata document") from error
        return result
    return _json_metadata(raw)


def _json_metadata(raw):
    if len(raw) > MAX_METADATA_BYTES:
        raise ValueError("metadata size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate metadata key")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite metadata")))
        _validate_metadata(result)
    except Exception as error:
        raise ValueError("unsupported metadata document") from error
    return result


def _validate_metadata(result):
    queue, count = [(result, 0)], 0
    while queue:
        value, depth = queue.pop()
        count += 1
        if depth > 50 or count > 100_000:
            raise ValueError("metadata structure limit")
        if isinstance(value, dict):
            queue.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            queue.extend((item, depth + 1) for item in value)


def _system_command(command):
    """Allow only exact read-only OS inventory commands, never user PATH."""
    command = tuple(map(str, command))
    allowed = {("/sbin/mount",), ("/usr/bin/dscl", ".", "-list", "/Users", "NFSHomeDirectory")}
    if hasattr(os, "getuid"):
        # Process names of this account only.
        uid = str(os.getuid())
        allowed |= {("/bin/ps", "-x", "-U", uid, "-o", "comm="), ("/bin/ps", "-U", uid, "-o", "comm=")}
    windows = os.name == "nt" and command == (str(_windows_system_directory() / "tasklist.exe"), "/FO", "CSV", "/NH",
                                              "/FI", "USERNAME eq " + _windows_user())
    if command not in allowed and not windows:
        raise ValueError("unsupported OS inventory command")
    first = command[0]
    env = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
    if windows:
        env = {"SystemRoot": str(Path(first).parent.parent)}
    result = subprocess.run(list(map(str, command)), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=str(Path(first).anchor), env=env, shell=False,
                            timeout=15, check=False)
    if result.returncode or len(result.stdout) > MAX_OS_OUTPUT_BYTES:
        raise ValueError("OS inventory unavailable or oversized")
    return result.stdout.decode("utf-8", "replace")


def _windows_user():
    """This account for tasklist's USERNAME filter, with its domain; a wildcard is refused."""
    name, domain = os.environ.get("USERNAME", ""), os.environ.get("USERDOMAIN", "")
    if not name or any(character in name + domain for character in '*"?\\'):
        raise ValueError("unsupported account name")
    return domain + "\\" + name if domain else name


def _windows_system_directory():
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    size = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if not size or size >= len(buffer):
        raise OSError("Windows system directory unavailable")
    return Path(buffer.value)


def _decode_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mounts(os_name):
    """Return local mount roots, blocked mountpoints, and a verified-index flag."""
    roots, blocked, network_count = [], [], 0
    if os_name == "windows":
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        if not mask:
            raise OSError("local drives unavailable")
        for index in range(26):
            if mask & (1 << index):
                root = Path(chr(65 + index) + ":\\")
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(str(root))
                if drive_type == 3:
                    roots.append(root)
                else:
                    blocked.append(root)
                    network_count += drive_type == 4
    elif os_name == "linux":
        # OS virtual metadata is intentionally read here; directory traversal
        # never enters /proc or other virtual filesystems.
        with open("/proc/self/mountinfo", "rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise ValueError("mount metadata size limit")
        for line in raw.decode("utf-8", "replace").splitlines():
            before, separator, after = line.partition(" - ")
            fields, tail = before.split(), after.split()
            if not separator or len(fields) < 5 or not tail:
                continue
            path = Path(_decode_mount(fields[4]))
            (roots if tail[0] in LOCAL_FS else blocked).append(path)
            network_count += tail[0] in NETWORK_FS
    elif os_name == "macos":
        for line in _system_command(["/sbin/mount"]).splitlines():
            match = re.search(r" on (.+) \(([^)]+)\)$", line)
            if not match:
                continue
            options = {part.strip() for part in match.group(2).split(",")}
            path = Path(match.group(1))
            (roots if options & LOCAL_FS and "local" in options else blocked).append(path)
            network_count += bool(options & NETWORK_FS)
    if not roots:
        raise ValueError("no local volume metadata")
    return list(dict.fromkeys(roots)), set(blocked), network_count


def _current_home(os_name):
    """The signed-in account's home, from a lookup of this account alone, never enumeration.

    Directory-service accounts (LDAP, Active Directory) are missing from local account files.
    """
    if os_name == "windows":
        return Path(os.environ["USERPROFILE"]) if os.environ.get("USERPROFILE") else None
    import pwd
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _profile_metadata(os_name):
    """Every person's account home, wherever it is, and the folders that hold account homes."""
    profiles, roots = [], []
    if os_name == "windows":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as key:
            try:
                directory = winreg.QueryValueEx(key, "ProfilesDirectory")[0]
                roots.append(Path(os.path.expandvars(directory)))
            except OSError:
                roots.append(Path(_windows_system_directory().anchor) / "Users")
            count = winreg.QueryInfoKey(key)[0]
            for index in range(count):
                try:
                    name = winreg.EnumKey(key, index)
                    # Local and domain (S-1-5-21) and Microsoft Entra (S-1-12-1) accounts are
                    # people, on any drive; system and service profiles use other identifiers.
                    if not name.startswith(("S-1-5-21-", "S-1-12-1-")):
                        continue
                    with winreg.OpenKey(key, name) as profile:
                        value = winreg.QueryValueEx(profile, "ProfileImagePath")[0]
                    profiles.append(Path(os.path.expandvars(value)))
                except OSError:
                    continue
    elif os_name == "linux":
        # Read the local account database, not NSS/LDAP enumeration.
        with open("/etc/passwd", "rb") as stream:
            raw = stream.read(MAX_METADATA_BYTES + 1)
        if len(raw) > MAX_METADATA_BYTES:
            raise ValueError("account metadata size limit")
        for line in raw.decode("utf-8", "replace").splitlines():
            fields = line.split(":")
            if len(fields) != 7 or not fields[2].isdigit():
                continue
            uid, path, shell = int(fields[2]), Path(fields[5]), fields[6].strip()
            # People, not service accounts: regular UIDs with a login shell.
            person = uid >= PERSON_UID_MINIMUM["linux"] and uid not in NOBODY_UIDS and shell not in NO_LOGIN_SHELLS
            if person and path.is_absolute() and path.parent != path and str(path) not in {"/nonexistent", "/var/empty", "/dev/null"}:
                profiles.append(path)
        roots = [Path("/home")]
    else:
        for line in _system_command(["/usr/bin/dscl", ".", "-list", "/Users", "NFSHomeDirectory"]).splitlines():
            fields = line.split(None, 1)
            if len(fields) == 2:
                name, path = fields[0], Path(fields[1].strip())
                # Daemon accounts (_www, root, nobody) and tool prefixes are not people; a
                # person's home can be relocated outside /Users.
                person = not name.startswith("_") and name not in {"root", "daemon", "nobody"}
                if person and path.is_absolute() and path.parent != path and path.name not in NON_ACCOUNT_PROFILE_NAMES and str(path) not in {"/var/empty", "/dev/null"}:
                    profiles.append(path)
        roots = [Path("/Users")]
    return profiles, roots


def _layout():
    os_name = {"darwin": "macos", "win32": "windows", "linux": "linux"}.get(sys.platform, "unsupported")
    layout = {"os": os_name, "roots": [], "blockedMounts": set(), "profiles": [],
              "profileRoots": [], "currentHome": None, "gaps": [], "mountIndexVerified": False}
    if os_name == "unsupported":
        layout["gaps"].append("This operating system has no implemented machine discovery adapter.")
        return layout
    try:
        layout["roots"], layout["blockedMounts"], layout["networkMountCount"] = _mounts(os_name)
        layout["mountIndexVerified"] = True
    except (OSError, ValueError, subprocess.SubprocessError):
        layout["gaps"].append("Local volume metadata could not be fully read; unknown cross-device paths are skipped.")
        layout["roots"] = [Path(_windows_system_directory().anchor)] if os_name == "windows" else [Path("/")]
    try:
        layout["currentHome"] = _current_home(os_name)
    except (OSError, KeyError, ImportError):
        layout["currentHome"] = None  # Reported by the profile step.
    try:
        layout["profiles"], layout["profileRoots"] = _profile_metadata(os_name)
    except (OSError, ValueError, ImportError, subprocess.SubprocessError):
        layout["gaps"].append("Operating-system user-profile metadata could not be completely enumerated.")
        layout["profileRoots"] = [Path("/Users")] if os_name == "macos" else [Path("/home"), Path("/root")] if os_name == "linux" else [Path(_windows_system_directory().anchor) / "Users"]
    return layout


class _Discovery:
    def __init__(self, layout, *, directory_limit=DEFAULT_DIRECTORY_LIMIT, entry_limit=DEFAULT_ENTRY_LIMIT, seconds=DEFAULT_SECONDS):
        self.layout = layout
        self.sources, self.observations, self.gaps = [], [], set()
        self.counts = {key: 0 for key in ("localVolumes", "profilesDiscovered", "profilesAccessible", "directoriesVisited", "entriesVisited", "projectsDiscovered", "permissionErrors", "symlinksSkipped", "networkMountsSkipped", "prunedDirectories")}
        self.counts["truncated"] = False
        self.directory_limit, self.entry_limit = directory_limit, entry_limit
        self.seconds = seconds
        self.deadline = time.monotonic() + seconds
        # Other accounts' homes; None until the profile step identifies them.
        self.accounts = None
        self.uid = os.getuid() if hasattr(os, "getuid") else None
        if layout.get("gaps"):
            source = self.source("operating-system-discovery-metadata")
            for reason in layout["gaps"]:
                self.gap(source, reason, "error")

    def source(self, label):
        identity = "src-" + _id("machine", label)
        item = next((source for source in self.sources if source["id"] == identity), None)
        if item is None:
            item = {"id": identity, "client": "machine", "scope": "machine", "location": "machine:" + label, "status": "collected", "reason": "read-only discovery completed"}
            self.sources.append(item)
        return item

    def step(self, label, run, fallback=None):
        """Run one discovery step; an unexpected failure is a gap, not a lost scan.

        Expected OS and filesystem errors are handled inside each step. Anything
        else (an unanticipated metadata shape or a defect) ends only this step:
        evidence it already recorded is kept and its source reports the failure.
        """
        try:
            return run()
        except Exception:
            self.gap(self.source(label), "This discovery step stopped unexpectedly; its results are incomplete.", "error")
            return fallback

    def gap(self, source, reason, status="skipped"):
        reasons = source.setdefault("reasons", [])
        if reason not in reasons:
            reasons.append(reason)
        if source.get("status") == "error":
            status = "error"
        source.update(status=status, reason=reason)
        self.gaps.add(source["location"] + ": " + reason)

    def error(self, source, error, path=None):
        denied = isinstance(error, PermissionError) or getattr(error, "errno", None) in {1, 13}
        if denied:
            self.counts["permissionErrors"] += 1
        if path is not None:
            # Preserve which discovery area failed, without exporting private
            # account/project/file names from filesystem exceptions.
            label = "area-" + _id("discovery-area", path)[:10]
            metadata = source.setdefault("metadata", {})
            areas = metadata.setdefault("affectedAreas", [])
            if label not in areas and len(areas) < 1000:
                areas.append(label)
            identity = "src-" + _id(source["id"], label)
            area = next((item for item in self.sources if item["id"] == identity), None)
            if area is None:
                area = {"id": identity, "client": "machine", "scope": "machine", "location": source["location"] + "/" + label, "status": "error"}
                self.sources.append(area)
            source = area
        self.gap(source, "Permission denied for this discovery area." if denied else "This discovery area could not be read safely.", "error")

    def indicator(self, source, client, activation, discovery, *, extra=None, kind="client"):
        details = {"activation": activation, "discovery": discovery, "interpretation": "OS process-name observation; executable identity and session access not verified" if activation == "running" else "installation metadata indicator; runtime state not verified"}
        details.update(extra or {})
        item = {"id": "obs-" + _id(source["id"], client, kind, len(self.observations)), "kind": kind, "client": client, "name": client if kind == "client" else "AI-related browser extension", "sourceId": source["id"], "location": source["location"], "enabled": "unknown", "details": details}
        self.observations.append(item)

    def children(self, path, source):
        try:
            if any(path == blocked or blocked in path.parents for blocked in self.layout.get("blockedMounts", set())):
                return []
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                self.counts["symlinksSkipped"] += 1
                return []
            # List the folder that was checked, through a handle opened without following a
            # final link and compared by identity, so a folder swapped in between is never listed.
            listed = path
            if os.scandir in os.supports_fd and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW"):
                listed = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                opened = os.fstat(listed)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    os.close(listed)
                    raise ValueError("directory changed while opening")
            try:
                with os.scandir(listed) as entries:
                    result = []
                    for item in entries:
                        result.append(path / item.name)
                        if len(result) > 100_000:
                            self.gap(source, "A discovery directory exceeded its 100,000-entry budget.")
                            self.counts["truncated"] = True
                            break
            finally:
                if listed is not path:
                    os.close(listed)
            return sorted(result)
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as error:
            self.error(source, error, path)
            return []

    def other_person(self, info):
        """Whether a directory is owned by another person's account (POSIX ownership)."""
        minimum = PERSON_UID_MINIMUM.get(self.layout.get("os"))
        uid = getattr(info, "st_uid", None)
        return (minimum is not None and self.uid is not None and uid is not None
                and uid != self.uid and uid >= minimum and uid not in NOBODY_UIDS)

    def usable_marker(self, path):
        """An AI marker this account owns, or a system account does; another person's is not."""
        try:
            return not self.other_person(path.lstat())
        except OSError:
            return False

    def profiles(self):
        """Return the scanning account's profile; no other account is opened.

        Other accounts' home directories are recorded first, so project discovery can
        skip them and their paths can be scrubbed, even when this account's own home
        cannot be opened.
        """
        source = self.source("local-user-profiles")
        paths = set(self.layout.get("profiles", []))
        current = self.layout.get("currentHome")
        for parent in self.layout.get("profileRoots", []):
            paths.update(child for child in self.children(parent, source)
                         if child.name not in NON_ACCOUNT_PROFILE_NAMES and not child.name.startswith("."))
        # Another spelling of this account's home (letter case, a Windows short name) is the
        # same directory, not another account.
        own = _identity(current) if current else None
        others = sorted((path for path in paths if path != current and path.is_absolute() and path.parent != path
                         and (own is None or _identity(path) != own)), key=str)
        # Aliases are stable ordinals, never names: ~ for this account, user-N for others.
        self.accounts = [{"root": path, "alias": "user-" + str(index)} for index, path in enumerate(others, 1)]
        self.counts["profilesExcluded"] = len(others)
        if not current or not current.is_absolute() or current.parent == current:
            self.gap(source, "The current account's home directory could not be determined.", "error")
            return []
        if str(current).startswith("\\\\") or any(current == blocked or blocked in current.parents for blocked in self.layout.get("blockedMounts", set())):
            self.gap(source, "The current account's profile is on a nonlocal or excluded filesystem and was not opened.")
            return []
        try:
            info = current.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                self.counts["symlinksSkipped"] += 1
                return []
            if not stat.S_ISDIR(info.st_mode):
                return []
            self.counts["profilesDiscovered"] += 1
            with os.scandir(current):
                pass
        except FileNotFoundError:
            return []
        except OSError as error:
            self.error(source, error, current)
            return []
        self.counts["profilesAccessible"] += 1
        return [{"root": current, "alias": "~"}]

    def projects(self, profiles, explicit):
        source = self.source("local-volume-project-discovery")
        self.deadline = time.monotonic() + self.seconds
        roots = list(dict.fromkeys(self.layout.get("roots", []) + [item["root"] for item in profiles]))
        self.counts["localVolumes"] = len(self.layout.get("roots", []))
        blocked = self.layout.get("blockedMounts", set())
        self.counts["networkMountsSkipped"] = self.layout.get("networkMountCount", 0)
        self.counts["nonLocalMountsSkipped"] = len(blocked)
        self.counts["excludedDirectories"] = 0
        profiles_set = {item["root"] for item in profiles}
        projects = {Path(item).absolute() for item in explicit}
        if self.accounts is None:
            # Other accounts' homes cannot be told apart from projects, so none is searched.
            self.gap(source, "Other accounts on this computer could not be identified, so local drives were not searched for projects.", "error")
            self.counts["projectsDiscovered"] = len(projects)
            return sorted(projects, key=str)
        # Other accounts' homes, OS temporary folders and this scanner's own folder are
        # never traversed. Directory identity is compared too, so a firmlink or bind mount
        # of an excluded folder stays excluded; this account's own home never is.
        excluded = {item["root"] for item in self.accounts}
        excluded.update(Path(path) for path in TEMPORARY_ROOTS.get(self.layout.get("os"), ()))
        if self.layout.get("os") == "windows":
            excluded.update(item["root"] / "AppData/Local/Temp" for item in profiles)
        excluded.add(SCANNER_ROOT)
        homes = profiles_set | ({self.layout["currentHome"]} if self.layout.get("currentHome") else set())

        def link_target(path):
            # A home that is a link or junction is excluded where it points, too. The target is
            # computed without following the link; it never covers a volume or this account's
            # home, and a nonlocal target is never looked up.
            try:
                info = path.lstat()
                if not (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400):
                    return None
                target = Path(os.path.normpath(path.parent / os.readlink(path)))
            except (OSError, ValueError):
                return None
            if (target.parent == target or any(home.is_relative_to(target) for home in homes)
                    or any(target == item or item in target.parents for item in blocked)):
                return None
            return target

        excluded |= set(map(link_target, excluded)) - {None}
        excluded -= profiles_set
        excluded_identities = set(map(_identity, excluded)) - set(map(_identity, profiles_set)) - {None}

        def outside_scope(root):
            # A volume mounted inside an excluded folder, or a backup, is not searched either.
            if any(part in PRUNE_NAMES for part in root.parts):
                return True
            for folder in (root, *root.parents):
                if folder in profiles_set:
                    return False
                if folder in excluded or _identity(folder) in excluded_identities:
                    return True
            return False

        other_names = {item["root"].name.casefold() for item in self.accounts} - {home.name.casefold() for home in homes}
        queue = deque()
        for root in roots:
            if root not in profiles_set and outside_scope(root):
                self.counts["excludedDirectories"] += 1
            else:
                queue.append((root, 0, None))
        seen = set()
        while queue:
            if self.counts["directoriesVisited"] >= self.directory_limit or self.counts["entriesVisited"] >= self.entry_limit or time.monotonic() >= self.deadline:
                self.counts["truncated"] = True
                self.gap(source, "Machine discovery reached its configured directory, entry, or time budget; remaining paths were not inspected.")
                break
            directory, depth, parent_device = queue.popleft()
            if directory in blocked:
                continue
            try:
                info = directory.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    self.counts["symlinksSkipped"] += 1
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    continue
                if parent_device is not None and info.st_dev != parent_device and not self.layout.get("mountIndexVerified"):
                    self.gap(source, "An unclassified mount was skipped because the local mount index was unavailable.")
                    continue
                identity = (info.st_dev, info.st_ino)
                if identity in seen:
                    continue
                seen.add(identity)
                if directory in excluded or identity in excluded_identities or self.other_person(info):
                    self.counts["excludedDirectories"] += 1
                    continue
                self.counts["directoriesVisited"] += 1
                children = self.children(directory, source)
                self.counts["entriesVisited"] += len(children)
                if directory not in profiles_set and directory.parent != directory and any(child.name in PROJECT_MARKERS and self.usable_marker(child) for child in children):
                    projects.add(directory)
                for child in children:
                    if child.name in PRUNE_NAMES or child.suffix.lower() == ".app":
                        self.counts["prunedDirectories"] += 1
                        continue
                    # A copy of another account's home, such as D:\Backup\Users\alice, on a disk
                    # that records no owner.
                    if child.name.casefold() in other_names and directory.name.casefold() in {"users", "home"}:
                        self.counts["excludedDirectories"] += 1
                        continue
                    # Native OS binary/system trees have dedicated inventories.
                    if directory.parent == directory and child.name in {"proc", "sys", "dev", "run", "bin", "sbin", "lib", "lib64", "usr", "System", "Windows"}:
                        self.counts["prunedDirectories"] += 1
                        continue
                    try:
                        child_info = child.lstat()
                        if (getattr(child_info, "st_flags", 0) or 0) & SF_DATALESS:
                            self.counts["prunedDirectories"] += 1  # Online-only: listing it would download it.
                            continue
                        if stat.S_ISDIR(child_info.st_mode) and not getattr(child_info, "st_file_attributes", 0) & 0x400:
                            if depth >= 128:
                                self.counts["truncated"] = True
                                self.gap(source, "A directory exceeded the 128-level discovery depth budget.")
                                continue
                            queue.append((child, depth + 1, info.st_dev))
                        elif stat.S_ISLNK(child_info.st_mode) or getattr(child_info, "st_file_attributes", 0) & 0x400:
                            self.counts["symlinksSkipped"] += 1
                    except OSError as error:
                        self.error(source, error, child)
            except OSError as error:
                self.error(source, error, directory)
        self.counts["projectsDiscovered"] = len(projects)
        return sorted(projects, key=str)

    def processes(self):
        """Names of AI apps this account is running; other accounts' processes are not listed."""
        source = self.source("running-process-names")
        os_name = self.layout["os"]
        try:
            if os_name not in {"windows", "macos", "linux"}:
                raise ValueError("unsupported OS")
            if os_name == "windows":
                command = [_windows_system_directory() / "tasklist.exe", "/FO", "CSV", "/NH", "/FI", "USERNAME eq " + _windows_user()]
            else:
                command = ["/bin/ps", *(["-x"] if os_name == "macos" else []), "-U", str(os.getuid()), "-o", "comm="]
            text = _system_command(command)
            names = [row[0] for row in csv.reader(io.StringIO(text)) if row] if os_name == "windows" else text.splitlines()
            found = set()
            for raw in names:
                name = raw.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
                if name.endswith(".exe"):
                    name = name[:-4]
                if name in EXECUTABLES and name not in {"agent", "cn"}:
                    found.add(EXECUTABLES[name])
            for client in sorted(found):
                self.indicator(source, client, "running", "operating-system-process-name")
        except (OSError, KeyError, ValueError, subprocess.SubprocessError):
            self.gap(source, "The fixed operating-system process inventory could not be read; running AI processes remain unverified.", "error")

    def services(self, profiles):
        """Read startup metadata, never invoke service controllers or scripts."""
        source = self.source("services-and-startup-metadata")
        known = {"ollama": "ollama", "openclaw": "openclaw", "openclaw-gateway": "openclaw"}
        found = set()
        os_name = self.layout["os"]
        if os_name == "windows":
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as key:
                    count = winreg.QueryInfoKey(key)[0]
                    for index in range(min(count, 100_000)):
                        name = winreg.EnumKey(key, index).lower()
                        if name in known:
                            found.add(known[name])
                    if count > 100_000:
                        self.gap(source, "The Windows service-key inventory exceeded its metadata budget.")
            except (OSError, ImportError) as error:
                self.error(source, error)
        elif os_name == "linux":
            roots = [Path("/etc/systemd/system"), Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")]
            roots.extend(item["root"] / ".config/systemd/user" for item in profiles)
            for root in roots:
                for path in self.children(root, source):
                    if path.suffix == ".service" and path.stem in known:
                        found.add(known[path.stem])
        elif os_name == "macos":
            roots = [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
            roots.extend(item["root"] / "Library/LaunchAgents" for item in profiles)
            for root in roots:
                for path in self.children(root, source):
                    if path.suffix != ".plist":
                        continue
                    try:
                        data = _regular_metadata(path, "plist")
                        if not isinstance(data, dict):
                            continue
                        program = data.get("Program")
                        args = data.get("ProgramArguments")
                        if not isinstance(program, str) and isinstance(args, list) and args:
                            program = args[0]
                        if isinstance(program, str):
                            name = Path(program).name.lower()
                            if name in EXECUTABLES and name not in {"agent", "cn", "code"}:
                                found.add(EXECUTABLES[name])
                    except FileNotFoundError:
                        pass
                    except (OSError, ValueError, RecursionError, plistlib.InvalidFileException) as error:
                        self.error(source, error, path)
        else:
            self.gap(source, "Service discovery is unsupported for this operating system.")
        for client in sorted(found):
            self.indicator(source, client, "installed", "operating-system-startup-metadata", extra={"interpretation": "AI startup/service declaration; running service status not verified"})

    def browser_extensions(self, profiles):
        source = self.source("browser-ai-extension-metadata")
        paths = {"macos": ["Library/Application Support/Google/Chrome", "Library/Application Support/Microsoft Edge", "Library/Application Support/BraveSoftware/Brave-Browser"], "linux": [".config/google-chrome", ".config/chromium", ".config/microsoft-edge", ".config/BraveSoftware/Brave-Browser"], "windows": ["AppData/Local/Google/Chrome/User Data", "AppData/Local/Microsoft/Edge/User Data", "AppData/Local/BraveSoftware/Brave-Browser/User Data"]}
        inspected = candidates = 0
        deadline = time.monotonic() + 120
        for account in profiles:
            for relative in paths.get(self.layout["os"], []):
                for profile in self.children(account["root"] / relative, source):
                    if profile.name != "Default" and not re.fullmatch(r"Profile \d+", profile.name):
                        continue
                    for extension in self.children(profile / "Extensions", source):
                        for version in self.children(extension, source):
                            if inspected >= 100_000 or time.monotonic() >= deadline:
                                self.gap(source, "Browser metadata discovery reached its manifest/time budget.")
                                source["metadata"] = {"manifestsInspected": inspected, "aiNameHints": candidates}
                                return
                            try:
                                data = _regular_metadata(version / "manifest.json")
                                if not isinstance(data, dict):
                                    continue
                                inspected += 1
                                name = data.get("name")
                                # Localized extension names are metadata too;
                                # resolve only the manifest's bounded default
                                # locale, without loading scripts or a browser.
                                if isinstance(name, str) and re.fullmatch(r"__MSG_[A-Za-z0-9_]{1,128}__", name):
                                    locale = data.get("default_locale")
                                    if isinstance(locale, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", locale):
                                        messages = _regular_metadata(version / "_locales" / locale / "messages.json")
                                        message = messages.get(name[6:-2], {}) if isinstance(messages, dict) else {}
                                        name = message.get("message") if isinstance(message, dict) else None
                                if not isinstance(name, str) or not AI_EXTENSION_NAME.search(name):
                                    continue
                                candidates += 1
                                permissions = data.get("permissions", [])
                                hosts = data.get("host_permissions", [])
                                safe_permissions = sorted({item for item in permissions if isinstance(item, str) and item in EXTENSION_PERMISSIONS}) if isinstance(permissions, list) else []
                                broad = any(item in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"} for item in hosts + permissions if isinstance(item, str)) if isinstance(hosts, list) and isinstance(permissions, list) else False
                                self.indicator(source, "browser-extensions", "present", "browser-extension-manifest-name-hint", kind="plugin", extra={"auditStatus": "not-assessed", "aiRelatedNameHint": True, "permissions": safe_permissions, "broadHostAccess": broad, "interpretation": "AI-related manifest name hint; identity, active browser state, and permissions not verified"})
                            except FileNotFoundError:
                                pass
                            except (OSError, ValueError, RecursionError) as error:
                                self.error(source, error, version / "manifest.json")
            firefox_roots = {"macos": "Library/Application Support/Firefox/Profiles", "windows": "AppData/Roaming/Mozilla/Firefox/Profiles", "linux": ".mozilla/firefox"}
            relative = firefox_roots.get(self.layout["os"])
            if not relative:
                continue
            for profile in self.children(account["root"] / relative, source):
                try:
                    if not stat.S_ISDIR(profile.lstat().st_mode):
                        continue
                    if inspected >= 100_000 or time.monotonic() >= deadline:
                        self.gap(source, "Browser metadata discovery reached its manifest/time budget.")
                        source["metadata"] = {"manifestsInspected": inspected, "aiNameHints": candidates}
                        return
                    data = _regular_metadata(profile / "extensions.json")
                    addons = data.get("addons", []) if isinstance(data, dict) else []
                    if not isinstance(addons, list):
                        raise ValueError("unsupported extension metadata")
                    for addon in addons:
                        if not isinstance(addon, dict):
                            continue
                        inspected += 1
                        locale = addon.get("defaultLocale")
                        name = locale.get("name") if isinstance(locale, dict) else None
                        if not isinstance(name, str) or not AI_EXTENSION_NAME.search(name):
                            continue
                        candidates += 1
                        grants = addon.get("userPermissions", {})
                        permissions = grants.get("permissions", []) if isinstance(grants, dict) else []
                        origins = grants.get("origins", []) if isinstance(grants, dict) else []
                        safe_permissions = sorted({value for value in permissions if isinstance(value, str) and value in EXTENSION_PERMISSIONS}) if isinstance(permissions, list) else []
                        broad = isinstance(origins, list) and any(value in {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"} for value in origins if isinstance(value, str))
                        self.indicator(source, "browser-extensions", "present", "firefox-extension-metadata-name-hint", kind="plugin", extra={"auditStatus": "not-assessed", "aiRelatedNameHint": True, "permissions": safe_permissions, "broadHostAccess": broad, "interpretation": "AI-related saved extension name hint; identity, active browser state, and effective permissions not verified"})
                except FileNotFoundError:
                    pass
                except (OSError, ValueError, RecursionError) as error:
                    self.error(source, error, profile / "extensions.json")
        source["metadata"] = {"manifestsInspected": inspected, "aiNameHints": candidates}


def _system_sources(os_name, discovery=None, *, environ=None):
    from .engine.paths import managed_candidates
    hints = os.environ if environ is None and discovery is not None else environ or {}
    recognized = {"PROGRAMFILES", "PROGRAMDATA", "GEMINI_CLI_SYSTEM_SETTINGS_PATH", "GEMINI_CLI_SYSTEM_DEFAULTS_PATH"}
    env = {}
    index_source = discovery.source("managed-policy-metadata") if discovery else None
    for key, value in hints.items():
        key = key.upper() if os_name == "windows" else key
        if key not in recognized or not value:
            continue
        pure = PureWindowsPath(value) if os_name == "windows" and isinstance(value, str) else Path(value) if isinstance(value, str) else None
        safe = pure is not None and pure.is_absolute() and pure.parent != pure and ".." not in pure.parts and len(value) <= 32768 and "\x00" not in value and not value.startswith(("\\\\", "//"))
        if safe and discovery:
            path = Path(value)
            outside = [*discovery.layout.get("blockedMounts", set()), *(item["root"] for item in discovery.accounts or ())]
            safe = not any(path == folder or folder in path.parents for folder in outside)
        if safe:
            env[key] = value
        elif discovery:
            discovery.gap(index_source, "Unsupported local system path override: " + key + ".")
    if os_name == "macos":
        claude, gemini = Path("/Library/Application Support/ClaudeCode"), Path("/Library/Application Support/GeminiCli")
        copilot, opencode = Path("/Library/Application Support/GitHubCopilot"), Path("/Library/Application Support/opencode")
    elif os_name == "windows":
        system_drive = Path(_windows_system_directory().anchor)
        env.setdefault("PROGRAMFILES", str(system_drive / "Program Files"))
        env.setdefault("PROGRAMDATA", str(system_drive / "ProgramData"))
        claude, gemini = Path(env["PROGRAMFILES"]) / "ClaudeCode", Path(env["PROGRAMDATA"]) / "gemini-cli"
        copilot, opencode = Path(env["PROGRAMFILES"]) / "GitHubCopilot", Path(env["PROGRAMDATA"]) / "opencode"
    else:
        claude, gemini = Path("/etc/claude-code"), Path("/etc/gemini-cli")
        copilot, opencode = Path("/etc/github-copilot"), Path("/etc/opencode")
    sources = []
    for candidate in managed_candidates(os_name, env):
        if candidate.role == "dropins":
            continue
        is_default = candidate.family == "gemini-cli" and candidate.location.endswith("system-defaults.json")
        sources.append({"path": candidate.path, "client": candidate.family, "location": "system:" + candidate.location.removeprefix("managed:"), "format": candidate.format, "context": "base" if is_default else "managed"})
    sources.extend([
        {"path": copilot / "managed-settings.json", "client": "copilot-cli", "location": "system:copilot-cli/managed-settings.json", "format": "jsonc", "context": "managed"},
        *({"path": opencode / name, "client": "opencode", "location": "system:opencode/" + name, "format": "jsonc", "context": "managed"} for name in ("opencode.json", "opencode.jsonc")),
    ])
    if discovery:
        for ordinal, path in enumerate(discovery.children(claude / "managed-settings.d", index_source), 1):
            if path.suffix == ".json":
                sources.append({"path": path, "client": "claude-code", "location": "system:claude-code/managed-settings.d/policy-" + str(ordinal) + ".json", "format": "json", "context": "managed"})
        if os_name == "macos":
            try:
                data = _regular_metadata(Path("/Library/Managed Preferences/com.anthropic.claudecode.plist"), "plist")
                if isinstance(data, dict):
                    sources.append({"data": data, "client": "claude-code", "location": "system:claude-code/managed-preferences", "format": "json", "context": "managed"})
            except FileNotFoundError:
                pass
            except (OSError, ValueError, RecursionError, plistlib.InvalidFileException) as error:
                discovery.error(index_source, error, Path("/Library/Managed Preferences/com.anthropic.claudecode.plist"))
        if os_name == "windows":
            try:
                import winreg
                for hive, label in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
                    try:
                        with winreg.OpenKey(hive, r"SOFTWARE\Policies\ClaudeCode") as key:
                            raw, kind = winreg.QueryValueEx(key, "Settings")
                        if not isinstance(raw, str):
                            raise ValueError("unsupported policy value")
                        data = _json_metadata(raw.encode("utf-8"))
                        if not isinstance(data, dict):
                            raise ValueError("unsupported policy shape")
                        sources.append({"data": data, "client": "claude-code", "location": "system:" + label + "/Software/Policies/ClaudeCode/Settings", "format": "json", "context": "managed"})
                    except FileNotFoundError:
                        pass
                    except (OSError, ValueError, RecursionError) as error:
                        discovery.error(index_source, error)
            except ImportError:
                discovery.gap(index_source, "Windows managed registry policy could not be inspected.")
    return list({(item["client"], str(item.get("path", item["location"])), item["context"]): item for item in sources}.values())


def _environment(os_name):
    containers, subsystems, sandbox = [], [], []
    for path, label in (("/.dockerenv", "docker-marker"), ("/run/.containerenv", "container-marker")):
        try:
            if Path(path).lstat():
                containers.append(label)
        except OSError:
            pass
    if os_name == "linux":
        try:
            with open("/proc/sys/kernel/osrelease", "rb") as stream:
                if b"microsoft" in stream.read(4096).lower():
                    subsystems.append("windows-subsystem-for-linux")
        except OSError:
            pass
    for variable, label in (("CODEX_SANDBOX", "agent-sandbox-environment-marker"), ("CODEX_SANDBOX_NETWORK_DISABLED", "agent-network-restriction-marker")):
        if os.environ.get(variable):
            sandbox.append(label)
    return {"visibility": "current-operating-system-context", "runtimeContext": "container" if containers else "unknown", "containerIndicators": containers, "subsystemIndicators": subsystems, "sandboxIndicators": sandbox, "isolation": "not-established"}


def _account_names(os_name):
    """The scanning account's login name, used only to scrub it from exported text."""
    try:
        if os_name == "windows":
            return {os.environ["USERNAME"]} if os.environ.get("USERNAME") else set()
        import pwd
        return {pwd.getpwuid(os.getuid()).pw_name}
    except (ImportError, KeyError, OSError):
        return set()


def identity_scrubber(current_home, others=(), names=()):
    """Scrub home paths, and the signed-in account's name, from exported text.

    This account's home and name are scrubbed even when its home could not be opened.
    Other accounts are never opened, so only their home paths can appear; their bare
    names are not rewritten, which could corrupt unrelated labels.
    """
    from .engine.redaction import IdentityScrubber
    own = {"root": current_home or "", "alias": "~", "names": {*names, *([Path(current_home).name] if current_home else [])}}
    return IdentityScrubber([own, *({"root": item["root"], "alias": item["alias"]} for item in others)])


def collect_machine(workspaces=None, *, directory_limit=DEFAULT_DIRECTORY_LIMIT, entry_limit=DEFAULT_ENTRY_LIMIT, seconds=DEFAULT_SECONDS):
    """Discover the scanning account's AI evidence on this machine.

    Scope: this account's profile, system and managed policy, installations, the AI
    apps this account is running, and AI projects on local volumes outside folders
    that belong to other accounts. Other accounts are never opened.
    """
    from .collector import collect_scopes
    from .dedup import merge_clients
    if any(type(value) is not int or value < 1 for value in (directory_limit, entry_limit, seconds)):
        raise ValueError("Machine discovery budgets must be positive integers.")
    started = datetime.now(timezone.utc).isoformat()
    layout = _layout()
    discovery = _Discovery(layout, directory_limit=directory_limit, entry_limit=entry_limit, seconds=seconds)
    # A failed profile step scans no profile: an unchecked home could be a network mount or a link.
    profiles = discovery.step("local-user-profiles", discovery.profiles, [])
    discovery.step("running-process-names", discovery.processes)
    # The retained baseline engine invoked by collect_scopes owns its richer
    # installation/MSIX/native-package/payload collectors; do not replace it
    # with name-only executable discovery here.
    discovery.step("services-and-startup-metadata", lambda: discovery.services(profiles))
    discovery.step("browser-ai-extension-metadata", lambda: discovery.browser_extensions(profiles))
    systems = discovery.step("managed-policy-metadata", lambda: _system_sources(layout["os"], discovery), [])
    explicit = sorted(dict.fromkeys(Path(item).absolute() for item in workspaces or []), key=str)
    projects = discovery.step("local-volume-project-discovery", lambda: discovery.projects(profiles, workspaces or []), explicit)
    environment = _environment(layout["os"])
    if environment["containerIndicators"]:
        source = discovery.source("runtime-context")
        discovery.gap(source, "Container indicators were observed; the outer host filesystem and processes are not verified.")
    # Environment overrides and search paths must not lead into other accounts or network disks.
    outside = [*(item["root"] for item in discovery.accounts or ()), *layout.get("blockedMounts", set())]
    snapshot = collect_scopes(profiles, system_sources=systems, workspaces=projects, scope_type="machine", discovery_gaps=sorted(discovery.gaps),
                              include_installations=True, excluded_roots=outside)
    snapshot["startedAt"] = started
    snapshot["completedAt"] = datetime.now(timezone.utc).isoformat()
    snapshot["sources"].extend(discovery.sources)
    snapshot["coverage"]["sourcesInspected"] = snapshot["coverage"].get("sourcesInspected", 0) + sum(item["status"] == "collected" for item in discovery.sources)
    snapshot["observations"] = merge_clients(snapshot["observations"] + discovery.observations)
    snapshot["scope"].update(platform=layout["os"], profileCount=len(profiles), workspaceCount=len(projects), discovery=discovery.counts, environment=environment)
    if discovery.gaps or any(item["status"] in {"error", "skipped"} for item in discovery.sources):
        snapshot["status"] = "partial"
    # Paths outside the scanned home (temporary folders, caches, other volumes) can
    # still embed an account's home or name. Remove both from every exported string.
    scrubber = identity_scrubber(layout.get("currentHome"), discovery.accounts or (), _account_names(layout["os"]))
    return scrubber.scrub_snapshot(snapshot)
