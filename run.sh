#!/usr/bin/env bash
# Start PromptGuard on http://127.0.0.1:5000 (local only).
set -e
cd "$(dirname "$0")"
python3 app.py --port "${PORT:-5000}"
