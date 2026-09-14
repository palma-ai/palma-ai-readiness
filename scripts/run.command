#!/usr/bin/env bash
# Finder launcher. Results go in a new readiness-run folder in your home folder.
here=$(cd "$(dirname "$0")" && pwd)
bash "$here/run.sh" "$@"
result=$?
if [ "$result" -eq 0 ]; then echo 'Finished. Your report is saved locally.'; fi
read -r -p 'Press Enter to close' _
exit "$result"
