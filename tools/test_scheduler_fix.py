#!/usr/bin/env python3
"""Test the scheduler context fix for sub_825968B0"""

import os
import sys
import subprocess
import time
import signal

def main():
    # Set environment variables
    env = os.environ.copy()
    env['MW05_TRACE_KERNEL'] = '1'
    env['MW05_SCHED_R3_EA'] = '0x00060E30'
    env['MW05_UNBLOCK_MAIN'] = '1'
    env['MW05_FORCE_PRESENT'] = '1'
    
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    
    # Delete old log
    if os.path.exists(log_path):
        os.remove(log_path)
        print(f"Deleted old log: {log_path}")
    
    print(f"Starting {exe_path} with scheduler context seeding...")
    print(f"Environment: MW05_SCHED_R3_EA=0x00060E30")
    
    # Start the process
    proc = subprocess.Popen(
        [exe_path],
        env=env,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
    )
    
    print(f"Process started with PID {proc.pid}")
    print("Waiting 20 seconds...")
    
    try:
        # Wait 20 seconds
        time.sleep(20)
        
        # Kill the process
        print(f"Terminating process {proc.pid}...")
        proc.terminate()
        
        # Wait for it to exit
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print("Process didn't terminate, killing...")
            proc.kill()
            proc.wait()
        
        print("Process terminated")
        
    except KeyboardInterrupt:
        print("\nInterrupted by user, terminating process...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    
    # Wait a bit for log to flush
    time.sleep(1)
    
    # Analyze the log
    print("\n" + "="*80)
    print("ANALYZING LOG FOR SCHEDULER CONTEXT SEEDING")
    print("="*80)
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total log lines: {len(lines)}")
    
    # Search for scheduler context related messages
    print("\n--- Searching for sub_825968B0 calls ---")
    found_825968B0 = False
    found_seeding = False
    found_seeded_from_env = False
    found_seeded_from_last = False
    found_still_invalid = False
    
    for i, line in enumerate(lines):
        if '825968B0' in line:
            found_825968B0 = True
            print(f"Line {i+1}: {line.rstrip()}")
            
            if 'attempting to seed' in line:
                found_seeding = True
            if 'seeded_from_env' in line:
                found_seeded_from_env = True
            if 'seeded_from_last' in line:
                found_seeded_from_last = True
            if 'still_invalid' in line:
                found_still_invalid = True
            
            # Only show first 30 occurrences
            if i > 30:
                break
    
    print("\n--- Summary ---")
    print(f"Found sub_825968B0 calls: {found_825968B0}")
    print(f"Found 'attempting to seed': {found_seeding}")
    print(f"Found 'seeded_from_env': {found_seeded_from_env}")
    print(f"Found 'seeded_from_last': {found_seeded_from_last}")
    print(f"Found 'still_invalid': {found_still_invalid}")
    
    # Search for missing initialization functions
    print("\n--- Searching for missing initialization functions ---")
    missing_funcs = ['82849DE8', '82881020', '82880FA0', '824411E0', '8284F548']
    for func in missing_funcs:
        found = False
        for line in lines:
            if func in line:
                found = True
                print(f"FOUND {func}: {line.rstrip()}")
                break
        if not found:
            print(f"NOT FOUND: {func}")
    
    # Search for thread creation
    print("\n--- Searching for thread creation ---")
    for i, line in enumerate(lines):
        if 'ExCreateThread' in line or 'CREATE_THREAD' in line:
            print(f"Line {i+1}: {line.rstrip()}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

