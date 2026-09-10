"""Read-only current-user Win32 package queries for explicitly known AI clients."""
import ctypes
import os
from pathlib import Path

from .filesystem import ReadGap
from .windows_products import CLAUDE_FAMILY, FULL_NAMES

MAX_PACKAGES, MAX_CHARACTERS = 32, 32768
# APPMODEL_ERROR_NO_PACKAGE: the family has no registered package for this user.
NO_PACKAGE = 15700


def load_api():
    if os.name != "nt":
        raise ReadGap("unknown_schema", "unsupported")
    try:
        # LOAD_LIBRARY_SEARCH_SYSTEM32 avoids a caller-controlled DLL search path.
        api = ctypes.WinDLL("kernel32.dll", winmode=0x800)
        count = ctypes.POINTER(ctypes.c_uint32)
        api.GetPackagesByPackageFamily.argtypes = [ctypes.c_wchar_p, count,
                                                   ctypes.POINTER(ctypes.c_wchar_p), count, ctypes.c_wchar_p]
        api.GetPackagePathByFullName.argtypes = [ctypes.c_wchar_p, count, ctypes.c_wchar_p]
        api.GetPackagesByPackageFamily.restype = ctypes.c_int32
        api.GetPackagePathByFullName.restype = ctypes.c_int32
        return api
    except (AttributeError, OSError):
        raise ReadGap("unknown_schema", "unsupported") from None


def check_result(result, *, sizing=False):
    if result == 0 or (sizing and result == 122):
        return
    if result == 5:
        raise ReadGap("permission_denied", "unreadable")
    raise ReadGap("io_error", "unreadable")


def package_full_names(api, package_family):
    count, length = ctypes.c_uint32(), ctypes.c_uint32()
    result = api.GetPackagesByPackageFamily(package_family, ctypes.byref(count), None, ctypes.byref(length), None)
    if result == NO_PACKAGE:
        return []
    check_result(result, sizing=True)
    if count.value > MAX_PACKAGES or length.value > MAX_CHARACTERS:
        raise ReadGap("count_limit")
    if count.value == 0:
        return []
    if not length.value:
        raise ReadGap("unknown_schema", "unsupported")
    capacity = count.value
    names = (ctypes.c_wchar_p * capacity)()
    buffer = ctypes.create_unicode_buffer(length.value)
    result = api.GetPackagesByPackageFamily(package_family, ctypes.byref(count), names, ctypes.byref(length), buffer)
    check_result(result)
    if count.value > capacity or length.value > len(buffer):
        raise ReadGap("count_limit")
    accepted = [name for name in names[:count.value] if isinstance(name, str) and len(name) <= 255
                and FULL_NAMES[package_family].fullmatch(name)]
    if count.value and not accepted:
        raise ReadGap("unknown_schema", "unsupported")
    return accepted


def package_path(api, full_name):
    length = ctypes.c_uint32()
    result = api.GetPackagePathByFullName(full_name, ctypes.byref(length), None)
    if result == NO_PACKAGE:
        return None  # removed between the two queries: absent, not unreadable
    check_result(result, sizing=True)
    if not 1 <= length.value <= MAX_CHARACTERS:
        raise ReadGap("count_limit")
    buffer = ctypes.create_unicode_buffer(length.value)
    result = api.GetPackagePathByFullName(full_name, ctypes.byref(length), buffer)
    if result == NO_PACKAGE:
        return None
    check_result(result)
    if length.value > len(buffer):
        raise ReadGap("count_limit")
    path = Path(buffer.value)
    if (not path.is_absolute() or path.parent == path or ".." in path.parts
            or buffer.value.startswith(("\\\\", "//"))):
        raise ReadGap("outside_scope")
    return path


def registered_packages(*, api=None, package_family=CLAUDE_FAMILY):
    if package_family not in FULL_NAMES:
        raise ReadGap("unknown_schema", "unsupported")
    api = api if api is not None else load_api()
    located = ((name, package_path(api, name)) for name in dict.fromkeys(package_full_names(api, package_family)))
    return [(name, path) for name, path in located if path is not None]
