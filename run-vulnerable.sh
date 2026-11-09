#!/usr/bin/env sh
set -eu
python3 app.py --mode vulnerable "$@"
