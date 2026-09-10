#!/usr/bin/env bash
# Finder launcher. Results go beside the skill folder.
here=$(cd "$(dirname "$0")" && pwd)
cd "$(dirname "$(dirname "$here")")" || exit 2
bash "$here/run.sh" "$@"
result=$?
if [ "$result" -eq 0 ]; then echo 'Finished. Your report is saved locally.'; fi
read -r -p 'Press Enter to close' _
exit "$result"
