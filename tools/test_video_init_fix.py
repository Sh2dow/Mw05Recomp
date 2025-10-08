#!/usr/bin/env python3
"""Test the video thread initialization fix"""

import os
import subprocess
import time
import signal

def main():
    print("="*80)
    print("TESTING VIDEO THREAD INITIALIZATION FIX")
    print("="*80)
    
    # Set environment variables
    env = os.environ.copy()
    env['MW05_FORCE_VIDEO_THREAD'] = '1'
    env['MW05_FORCE_VIDEO_THREAD_TICK'] = '250'
    env['MW05_UNBLOCK_MAIN'] = '1'
    env['MW05_FORCE_PRESENT'] = '1'
    env['MW05_SCHED_R3_EA'] = '0x00060E30'
    env['MW05_TRACE_KERNEL'] = '1'
    
    # Delete old log
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    if os.path.exists(log_path):
        os.remove(log_path)
        print(f"Deleted old log: {log_path}")
    
    # Run the game for 20 seconds
    print("\nStarting game for 20 seconds...")
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    
    proc = subprocess.Popen(
        [exe_path],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
    )
    
    try:
        # Wait for 20 seconds
        time.sleep(20)
    finally:
        # Terminate the process
        print("\nTerminating game...")
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            proc.wait(timeout=5)
        except:
            proc.kill()
            proc.wait()
        print("Game terminated")
    
    # Analyze the log
    print("\n" + "="*80)
    print("ANALYZING LOG")
    print("="*80)
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_content = f.read()
    
    # Check for the new initialization trigger
    print("\n--- Checking for video thread initialization trigger ---")
    if 'ForceVideoThread.trigger' in log_content:
        print("✓ Video thread initialization trigger FOUND")
        
        # Extract the trigger line
        for line in log_content.split('\n'):
            if 'ForceVideoThread.trigger' in line:
                print(f"  {line}")
                break
    else:
        print("✗ Video thread initialization trigger NOT found")
    
    # Check for sub_82849DE8 call
    print("\n--- Checking for sub_82849DE8 call ---")
    if 'ForceVideoThread.call_sub_82849DE8' in log_content:
        print("✓ sub_82849DE8 call FOUND")
        
        # Extract the call line
        for line in log_content.split('\n'):
            if 'ForceVideoThread.call_sub_82849DE8' in line:
                print(f"  {line}")
                break
    else:
        print("✗ sub_82849DE8 call NOT found")
    
    # Check for sub_82849DE8 in the log (should be called now)
    print("\n--- Checking if sub_82849DE8 was executed ---")
    if '82849DE8' in log_content:
        print("✓ sub_82849DE8 WAS executed")
        
        # Count occurrences
        count = log_content.count('82849DE8')
        print(f"  Found {count} references to sub_82849DE8")
        
        # Show first few occurrences
        lines = [l for l in log_content.split('\n') if '82849DE8' in l]
        print(f"\n  First 5 occurrences:")
        for line in lines[:5]:
            print(f"    {line}")
    else:
        print("✗ sub_82849DE8 was NOT executed")
    
    # Check for video thread creation
    print("\n--- Checking for video thread creation ---")
    if 'ExCreateThread' in log_content:
        print("✓ Thread creation calls FOUND")
        
        # Extract thread creation lines
        lines = [l for l in log_content.split('\n') if 'ExCreateThread' in l]
        print(f"  Found {len(lines)} thread creation calls:")
        for line in lines:
            print(f"    {line}")
    else:
        print("✗ No thread creation calls found")
    
    # Check for errors or crashes
    print("\n--- Checking for errors ---")
    error_keywords = ['ERROR', 'CRASH', 'EXCEPTION', 'FATAL', 'NULL-CALL']
    found_errors = False
    for keyword in error_keywords:
        if keyword in log_content:
            found_errors = True
            lines = [l for l in log_content.split('\n') if keyword in l]
            print(f"  Found {len(lines)} lines with '{keyword}':")
            for line in lines[:3]:  # Show first 3
                print(f"    {line}")
    
    if not found_errors:
        print("  No errors found")
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())

