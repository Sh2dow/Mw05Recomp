#!/usr/bin/env python3
"""Test baseline game execution without forced graphics callback."""

import subprocess
import time
import os

# Log directory for debug outputs
LOG_DIR = r'.\out\build\x64-Clang-Debug\Mw05Recomp'

# Set environment to disable forced graphics callback
env = os.environ.copy()
env['MW05_FORCE_GFX_NOTIFY_CB'] = '0'

print("Running baseline test (no forced graphics callback)...")
print("Game will run for 20 seconds...")

# Start the game
proc = subprocess.Popen(
    [r'.\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=env,
    text=True
)

# Wait for 20 seconds
time.sleep(20)

# Kill the process if still running
if proc.poll() is None:
    print("Terminating game after 20 seconds...")
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
else:
    print(f"Game exited with code: {proc.returncode}")

# Get output
stdout, stderr = proc.communicate()

# Save to files
with open(os.path.join(LOG_DIR, 'baseline_stdout.txt'), 'w') as f:
    f.write(stdout)
with open(os.path.join(LOG_DIR, 'baseline_stderr.txt'), 'w') as f:
    f.write(stderr)

# Print last 30 lines of stderr
print("\n=== Last 30 lines of stderr ===")
stderr_lines = stderr.strip().split('\n')
for line in stderr_lines[-30:]:
    print(line)

print("\n=== Test complete ===")

