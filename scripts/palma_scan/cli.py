"""Local collection, evaluation and report rebuilding."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import webbrowser

from . import __version__
from .model import booking_link, json_text, read_snapshot, summarize, validate


def parser():
    root = argparse.ArgumentParser(description="Palma AI access scan. Local discovery and evidence for the signed-in account, with no sign-up or network service.")
    root.add_argument("--version", action="version", version=f"Palma AI access scan {__version__}")
    commands = root.add_subparsers(dest="command", required=True)
    for name, help_text in (("run", "Scan and generate the local report"), ("collect", "Collect and evaluate local configuration evidence")):
        child = commands.add_parser(name, help=help_text)
        child.add_argument("--copied-home", type=Path, help="Offline inspection of a home-directory copy instead of this machine")
        child.add_argument("--home", dest="copied_home", type=Path, help=argparse.SUPPRESS)
        child.add_argument("--workspace", action="append", default=[], type=Path, help="Include an additional project beyond automatic machine discovery (repeatable)")
        if name == "run":
            child.add_argument("--output-dir", type=Path, help="New directory for the results (default: a new readiness-run folder in your home folder)")
            render_options(child)
        else:
            child.add_argument("--output", required=True, type=Path, help="New snapshot JSON file")
    for name, help_text in (("report", "Rebuild HTML from saved evidence"), ("summary", "Show counts without inventory names"), ("evaluate", "Apply bundled rules to saved evidence")):
        child = commands.add_parser(name, help=help_text)
        source = child.add_mutually_exclusive_group(required=True)
        source.add_argument("--report", type=Path, help="Saved snapshot.json")
        source.add_argument("--run-dir", type=Path, help="Directory containing snapshot.json")
        child.add_argument("--output", type=Path, required=name == "evaluate", help="New output file (existing files are never replaced)")
        if name == "report":
            render_options(child)
            child.add_argument("--share", action="store_true", help="Render the shareable summary: locations without project or folder names")
    return root


def render_options(child):
    child.add_argument("--booking-url", help="Override the default Palma booking link with an HTTPS palma.ai page; click-through only")
    child.add_argument("--open", dest="open_report", action="store_true", help="Open the generated local HTML file")
    child.add_argument("--no-open", dest="open_report", action="store_false", help="Keep the browser closed")
    child.set_defaults(open_report=False)


def write_new(path, text):
    """Exclusive creation protects previous evidence and refuses destination symlinks."""
    path = Path(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def scope(args):
    home = args.copied_home.expanduser().absolute() if args.copied_home else None
    projects = list(dict.fromkeys(path.expanduser().absolute() for path in args.workspace))
    for path in ([home] if home else []) + projects:
        if not path.is_dir() or path == Path(path.anchor):
            raise ValueError("Scan roots must be existing directories, not a filesystem root.")
        if home and path in projects and home.is_relative_to(path) and path != home:
            raise ValueError("A workspace must not contain the whole home directory.")
    return home, projects


def home_folder():
    """This account's home from the account database, not the HOME variable."""
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        return Path.home()


def shown(path):
    """A path for messages. Under the home folder it starts with ~, so output names no account."""
    path = Path(path).absolute()
    try:
        return str(Path("~") / path.relative_to(home_folder()))
    except ValueError:
        return str(path)


def open_local(path, enabled):
    # Without a display, Linux would start a text-mode browser in the foreground and wait.
    if enabled and sys.platform.startswith("linux") and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        enabled = False
        print("The report is saved. Open report.html in a browser to view it.")
    if enabled:
        try:
            opened = webbrowser.open(path.resolve().as_uri())
        except (OSError, webbrowser.Error):
            opened = False
        if not opened:
            print("The report is saved. Open report.html in your browser to view it.")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        link = booking_link(getattr(args, "booking_url", None))
        if args.command in {"run", "collect"}:
            home, projects = scope(args)
            from .rules import evaluate
            output = args.output if args.command == "collect" else args.output_dir
            if output is not None and (output.exists() or output.is_symlink()):
                raise ValueError("Output already exists. Choose a new path to preserve the previous run.")
            if home is not None:
                from .collector import collect
                snapshot = collect(home, projects, scope_type="copied-home")
            else:
                from .machine import collect_machine
                snapshot = collect_machine(projects)
            snapshot["findings"] = evaluate(snapshot)
            validate(snapshot)
            if args.command == "collect":
                write_new(output, json_text(snapshot))
                print(f"Local evidence: {shown(output)}")
            else:
                from .report import render_report
                summary = summarize(snapshot)
                html = render_report(snapshot, summary, booking_url=link)
                shareable = render_report(snapshot, summary, booking_url=link, share=True)
                # Not the working directory: results must not land inside a project or skill folder.
                output = output or home_folder() / ("readiness-run-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f"))
                output.mkdir(mode=0o700)
                write_new(output / "snapshot.json", json_text(snapshot))
                write_new(output / "summary.json", json_text(summary))
                write_new(output / "report.html", html)
                write_new(output / "share.html", shareable)
                print(f"Local report: {shown(output / 'report.html')}")
                print(f"Shareable summary (no project or folder names): {shown(output / 'share.html')}")
                print(f"Coverage: {snapshot['status']}. {len(snapshot['findings'])} findings to review. Nothing was sent by the scanner.")
                open_local(output / "report.html", args.open_report)
        else:
            snapshot = read_snapshot(args.report or args.run_dir / "snapshot.json")
            if args.command == "summary":
                result = json_text(summarize(snapshot))
                if args.output:
                    write_new(args.output, result)
                else:
                    print(result, end="")
            elif args.command == "evaluate":
                from .rules import evaluate
                if snapshot["mode"] != "endpoint":
                    raise ValueError("Deterministic endpoint rules require endpoint evidence; preserve declared findings separately.")
                snapshot["findings"] = evaluate(snapshot)
                from .governance import RULES_VERSION
                snapshot["collector"]["rulesVersion"] = RULES_VERSION
                write_new(args.output, json_text(validate(snapshot)))
                print(f"Local evaluated evidence: {shown(args.output)}")
            else:
                from .report import render_report
                output = args.output or (args.run_dir or args.report.parent) / ("share-rebuilt.html" if args.share else "report-rebuilt.html")
                write_new(output, render_report(snapshot, summarize(snapshot), booking_url=link, share=args.share))
                print(f"Local report: {shown(output)}")
                open_local(output, args.open_report)
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as error:
        # Do not echo raw document contents from parser errors or exception reprs.
        message = (str(error) if isinstance(error, ValueError)
                   else "Could not read or write the requested local artifacts. Check paths and permissions." if isinstance(error, OSError)
                   else "The evidence has an unsupported field type or nesting, so nothing was written.")
        print(f"Palma: {message}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Palma: interrupted before the command completed.", file=sys.stderr)
        return 130
    except Exception as error:
        # Last resort: a traceback or exception text can echo local file contents.
        # The exception class is enough to report a defect.
        print(f"Palma: the command stopped because of an unexpected internal error ({type(error).__name__}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
