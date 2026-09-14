"""Read only regular files beneath approved roots with shared collection budgets."""
import os
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path


def is_reparse_point(info):
    """Python 3.11 exposes Windows junctions through lstat attributes."""
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def path_is_redirect(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(info.st_mode) or is_reparse_point(info)


def platform_path(path):
    """Resolve only macOS's documented top-level aliases, never client links."""
    if sys.platform != "darwin" or len(path.parts) < 2 or path.parts[1] not in {"var", "tmp", "etc"}:
        return path
    alias = Path("/") / path.parts[1]
    target = Path("/private") / path.parts[1]
    try:
        if alias.parent / os.readlink(alias) == target:
            return target.joinpath(*path.parts[2:])
    except OSError:
        pass
    return path


class ReadGap(Exception):
    def __init__(self, reason: str, status: str = "skipped"):
        super().__init__(reason)
        self.reason, self.status = reason, status


@dataclass
class Budget:
    options: object
    started: float
    bytes_read: int = 0
    files_read: int = 0
    entries_seen: int = 0

    def check(self):
        if time.monotonic() - self.started >= self.options.max_seconds:
            raise ReadGap("time_limit")
        if self.files_read >= self.options.max_files:
            raise ReadGap("count_limit")


class SafeFiles:
    def __init__(self, roots: list[Path], budget: Budget, exact_files=(), account_uid=None):
        self.roots = []
        for root in sorted({root.absolute() for root in roots}, key=lambda root: len(root.parts)):
            if root.parent == root or ".." in root.parts:
                raise ValueError("unsafe collection root")
            if not any(root.is_relative_to(parent) for parent in self.roots):
                self.roots.append(root)
        self.exact_files = {path.absolute() for path in exact_files}
        self.budget = budget
        self.account_uid = account_uid

    def _boundary(self, path):
        root = next((root for root in self.roots if path.is_relative_to(root)), None)
        if root is not None:
            return root
        if path in self.exact_files:
            return path.parent
        raise ReadGap("outside_scope")

    def _open(self, path: Path, flags: int):
        path = self.approve(path)
        if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
            return os.open(path, flags)
        # Start at the filesystem anchor so a replaced ancestor above an
        # approved candidate directory cannot bypass O_NOFOLLOW.
        root = Path(path.anchor)
        relative = path.relative_to(root).parts
        if not relative:
            return os.open(root, flags | os.O_NOFOLLOW)
        # Traversal needs search permission, not permission to list ancestors.
        access = getattr(os, "O_PATH", getattr(os, "O_SEARCH", os.O_RDONLY))
        directory_flags = access | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(root, directory_flags)
        try:
            for component in relative[:-1]:
                child = os.open(component, directory_flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return os.open(relative[-1], flags | os.O_NOFOLLOW, dir_fd=descriptor)
        finally:
            os.close(descriptor)

    def _read_bytes(self, descriptor, maximum):
        chunks, count = [], 0
        while count <= maximum:
            self.budget.check()
            chunk = os.read(descriptor, min(65536, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        return b"".join(chunks)

    def approve(self, path: Path):
        path = path.absolute()
        if "\x00" in str(path):
            raise ReadGap("parse_error", "invalid")
        if ".." in path.parts:
            raise ReadGap("outside_scope")
        self._boundary(path)
        path = platform_path(path)
        current = path
        while True:
            self._reject_redirect(current)
            if current == current.parent:
                break
            current = current.parent
        return path

    def _reject_redirect(self, path):
        try:
            if path_is_redirect(path):
                raise ReadGap("symlink")
        except PermissionError as error:
            raise ReadGap("permission_denied", "unreadable") from error
        except ValueError as error:
            raise ReadGap("parse_error", "invalid") from error
        except OSError as error:
            raise ReadGap("io_error", "unreadable") from error

    def info(self, path: Path):
        self.budget.check()
        try:
            return self.approve(path).lstat()
        except FileNotFoundError as error:
            raise ReadGap("not_found", "absent") from error
        except PermissionError as error:
            raise ReadGap("permission_denied", "unreadable") from error
        except OSError as error:
            raise ReadGap("io_error", "unreadable") from error

    def read(self, path: Path) -> tuple[bytes, os.stat_result]:
        info = self.info(path)
        if not stat.S_ISREG(info.st_mode):
            raise ReadGap("unknown_schema", "unsupported")
        if info.st_size > self.budget.options.max_file_bytes:
            raise ReadGap("size_limit")
        available = self.budget.options.max_total_bytes - self.budget.bytes_read
        if info.st_size > available:
            raise ReadGap("size_limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = None
        try:
            descriptor = self._open(path, flags)
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise ReadGap("io_error", "unreadable")
            # A hard link can place another account's file inside a scanned folder.
            if self.account_uid is not None and opened.st_nlink > 1 and opened.st_uid not in {self.account_uid, 0}:
                raise ReadGap("outside_scope")
            maximum = min(self.budget.options.max_file_bytes, available)
            raw = self._read_bytes(descriptor, maximum)
            self.budget.files_read += 1
            self.budget.bytes_read += len(raw)
            if len(raw) > maximum:
                raise ReadGap("size_limit")
            return raw, opened
        except PermissionError as error:
            raise ReadGap("permission_denied", "unreadable") from error
        except OSError as error:
            raise ReadGap("io_error", "unreadable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def children(self, directory: Path) -> list[Path]:
        info = self.info(directory)
        if not stat.S_ISDIR(info.st_mode):
            raise ReadGap("unknown_schema", "unsupported")
        children = []
        descriptor = None
        try:
            target = self.approve(directory)
            if os.scandir in os.supports_fd and hasattr(os, "O_DIRECTORY"):
                descriptor = self._open(directory, os.O_RDONLY | os.O_DIRECTORY)
                target = descriptor
            with os.scandir(target) as entries:
                for entry in entries:
                    self.budget.check()
                    self.budget.entries_seen += 1
                    if self.budget.entries_seen > self.budget.options.max_files * 8:
                        raise ReadGap("count_limit")
                    children.append(directory / entry.name)
        except PermissionError as error:
            raise ReadGap("permission_denied", "unreadable") from error
        except OSError as error:
            raise ReadGap("io_error", "unreadable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return sorted(children, key=lambda path: path.name)
