"""Bounded known-client installation paths; no package-manager or general package scan."""
from pathlib import Path

from .identity import fingerprint
from .paths import Candidate

# A test can replace this tuple without redirecting the account's own Applications.
MAC_APPLICATION_ROOTS = (Path("/Applications"),)
SYSTEM_NPM_ROOTS = (Path("/usr/local/lib/node_modules"),)
MAC_NPM_ROOTS = (Path("/opt/homebrew/lib/node_modules"),)
LINUX_EDITOR_ROOTS = (("vscode", Path("/usr/share/code")), ("vscode", Path("/usr/share/code-insiders")))
CLI_PACKAGES = {"@anthropic-ai/claude-code": ("claude-code", "claude"),
                "@openai/codex": ("codex", "codex"), "@google/gemini-cli": ("gemini-cli", "gemini")}


def installed_candidate(family, path, label, role, format_name="directory", variant="cli"):
    return Candidate(family, "installation", path, "installation:" + label, format_name,
                     role, "installation:" + fingerprint(str(path)), variant)


def installed_client_candidates(home, os_name, environ, *, discover_os_packages=True):
    result = []
    if os_name == "windows":
        from .installation_windows import windows_msix_candidates
        from .windows_editors import windows_editor_candidates
        result.extend(windows_msix_candidates(home, discover_os_packages=discover_os_packages))
        result.extend(windows_editor_candidates(home, discover_os_packages=discover_os_packages))
        local = Path(environ.get("LOCALAPPDATA", str(home / "AppData/Local")))
        result.append(installed_candidate("kiro", local / "Kiro-Cli/kiro-cli.exe",
                                          "kiro-native-windows", "installed-binary-windows", "executable"))
    if os_name == "macos":
        for index, path in enumerate([*MAC_APPLICATION_ROOTS, home / "Applications"]):
            result.append(installed_candidate("unknown", path, f"macos-apps-{index}", "installed-apps"))
        result.append(installed_candidate("claude-code", home / "Library/Application Support/Claude/claude-code",
                                          "claude-desktop-embedded-versions", "installed-desktop-versions"))
    role = "installed-versions-windows" if os_name == "windows" else "installed-versions"
    result.append(installed_candidate("claude-code", home / ".local/share/claude/versions", "claude-native-versions", role))
    binaries = {"claude-code": "claude"}
    if os_name != "windows":
        binaries["cursor"] = "cursor-agent"
    if os_name == "linux":
        binaries["kiro"] = "kiro-cli"
    for family, binary in binaries.items():
        suffix = ".exe" if os_name == "windows" else ""
        role = "installed-binary-windows" if os_name == "windows" else "installed-binary"
        result.append(installed_candidate(family, home / ".local/bin" / (binary + suffix),
                                          "local-bin/" + binary, role, "executable"))
    if os_name != "windows":
        result.append(installed_candidate("cursor", home / ".local/share/cursor-agent/versions",
                                          "cursor-agent-native-versions", "installed-cursor-versions"))
    codex_roots = [home / ".codex"]
    if environ.get("CODEX_HOME"):
        codex_roots.append(Path(environ["CODEX_HOME"]).expanduser())
    result.extend(installed_candidate("codex", root / "packages/standalone/releases",
                                     f"codex-standalone-{index}", "installed-codex-releases")
                  for index, root in enumerate(dict.fromkeys(codex_roots)))
    result.extend(editor_installations(home, os_name, environ))
    result.extend(cli_package_candidates(home, os_name, environ))
    return list({(str(item.path), item.role): item for item in result}.values())


def editor_installations(home, os_name, environ):
    entries = []
    if os_name == "windows":
        local = Path(environ.get("LOCALAPPDATA", str(home / "AppData/Local")))
        programs = Path(environ.get("PROGRAMFILES", "C:/Program Files"))
        for root in (local / "Programs", programs):
            entries.extend([("vscode", root / "Microsoft VS Code"),
                            ("vscode", root / "Microsoft VS Code Insiders"), ("cursor", root / "cursor")])
    elif os_name == "linux":
        entries = LINUX_EDITOR_ROOTS
    return [installed_candidate(family, root / "resources/app/package.json", f"{os_name}-editor-{index}",
                                "installed-editor-" + os_name, "json", "ide")
            for index, (family, root) in enumerate(entries)]


def cli_package_candidates(home, os_name, environ):
    if os_name == "windows":
        appdata = Path(environ.get("APPDATA", str(home / "AppData/Roaming")))
        roots = [appdata / "npm/node_modules"]
    else:
        roots = [*SYSTEM_NPM_ROOTS, home / ".npm-global/lib/node_modules"]
        if os_name == "macos":
            roots.extend(MAC_NPM_ROOTS)
    separator = ";" if os_name == "windows" else ":"
    for directory in environ.get("PATH", "").split(separator)[:100]:
        path = Path(directory)
        if directory and path.is_absolute() and path.parent != path and ".." not in path.parts:
            if os_name == "windows":
                roots.append(path / "node_modules")
            elif path.name == "bin":
                roots.append(path.parent / "lib/node_modules")
    result = []
    for index, root in enumerate(dict.fromkeys(roots)):
        for package, (family, _) in CLI_PACKAGES.items():
            result.append(installed_candidate(family, root / package / "package.json",
                                              f"known-npm-prefix-{index}/{package}", "installed-package", "json"))
    # Legacy local Claude install: an exact known package, never its dependencies.
    result.append(installed_candidate("claude-code", home / ".claude/local/node_modules/@anthropic-ai/claude-code/package.json",
                                      "claude-legacy-package", "installed-package", "json"))
    return result


def installation_roots(candidates):
    roots = []
    for candidate in candidates:
        if candidate.format == "directory":
            roots.append(candidate.path)
        elif candidate.role == "installed-package":
            roots.append(candidate.path.parent)
        elif candidate.role.startswith("installed-editor-"):
            roots.append(candidate.path.parents[2])
        elif candidate.role == "installed-windows-msix" and not candidate.query_status:
            roots.append(candidate.path.parent)
        elif candidate.role == "installed-windows-editor" and not candidate.query_status:
            roots.append(candidate.path.parent)
    return roots
