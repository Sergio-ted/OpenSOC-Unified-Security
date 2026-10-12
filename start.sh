#!/bin/sh
set -eu
cd "$(dirname "$0")"
if command -v python3 >/dev/null 2>&1; then
  exec python3 app.py
fi
echo "Se requiere Python 3.10 o superior" >&2
exit 1
