#!/usr/bin/env python3
"""Test to find where the game is hanging during initialization"""

import os
import subprocess
import time
import signal

def main():
    print("="*80)
    print("TESTING HANG LOCATION")
    print("="*80)
    
    # Set environment variables
    env = os.environ.copy()
    env['MW05_TRACE_KERNEL'] = '1'
    
    # Delete old log
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    if os.path.exists(log_path):
        os.remove(log_path)
        print(f"Deleted old log: {log_path}")
    
    # Run the game for 5 seconds
    print("\nStarting game for 5 seconds...")
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    
    proc = subprocess.Popen(
        [exe_path],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )
    
    try:
        # Wait for 5 seconds
        time.sleep(5)
    finally:
        # Terminate the process
        print("\nTerminating game...")
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            stdout, stderr = proc.communicate(timeout=5)
        except:
            proc.kill()
            stdout, stderr = proc.communicate()
        print("Game terminated")
    
    # Analyze the log
    print("\n" + "="*80)
    print("LOG FILE ANALYSIS")
    print("="*80)
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_lines = f.readlines()
    
    print(f"Log file lines: {len(log_lines)}")
    
    # Show all lines
    print("\nALL LOG LINES:")
    for i, line in enumerate(log_lines, 1):
        print(f"{i:3d}: {line.rstrip()}")
    
    # Check for specific markers
    markers = [
        'sub_82621640.install',
        'after_sub_82621640_install',
        'sub_8284E658.install',
        'after_sub_8284E658_install',
        'before_KeTlsAlloc_install',
        'KeTlsAlloc.install',
        'sub_826346A8.install',
        'sub_82812ED0.install',
        'sub_828134E0.install',
        'before_unblock',
        'before_guest_start',
        'GuestThread.Start',
    ]
    
    print("\n" + "="*80)
    print("MARKER ANALYSIS")
    print("="*80)
    for marker in markers:
        found = any(marker in line for line in log_lines)
        status = "✓" if found else "✗"
        print(f"{status} {marker}")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())

