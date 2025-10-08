#!/usr/bin/env python3
"""Run find_82548F18_caller.py and limit output"""

import subprocess
import sys

result = subprocess.run(
    [sys.executable, 'tools/find_82548F18_caller.py'],
    capture_output=True,
    text=True,
    encoding='utf-8',
    errors='ignore'
)

lines = result.stdout.split('\n')
print('\n'.join(lines[:300]))

if len(lines) > 300:
    print(f"\n... (output truncated, {len(lines)} total lines)")

