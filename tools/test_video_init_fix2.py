#!/usr/bin/env python3
"""Test the video thread initialization fix - capture stderr"""

import os
import subprocess
import time
import signal

def main():
    print("="*80)
    print("TESTING VIDEO THREAD INITIALIZATION FIX (with stderr capture)")
    print("="*80)
    
    # Set environment variables
    env = os.environ.copy()
    env['MW05_FORCE_VIDEO_THREAD'] = '1'
    env['MW05_FORCE_VIDEO_THREAD_TICK'] = '50'  # Lower tick to trigger faster
    env['MW05_UNBLOCK_MAIN'] = '1'
    env['MW05_FORCE_PRESENT'] = '1'
    env['MW05_SCHED_R3_EA'] = '0x00060E30'
    env['MW05_TRACE_KERNEL'] = '1'
    
    # Delete old log
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    if os.path.exists(log_path):
        os.remove(log_path)
        print(f"Deleted old log: {log_path}")
    
    # Run the game for 10 seconds
    print("\nStarting game for 10 seconds...")
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    
    stderr_output = []
    
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
        # Wait for 10 seconds
        time.sleep(10)
    finally:
        # Terminate the process
        print("\nTerminating game...")
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            stdout, stderr = proc.communicate(timeout=5)
            stderr_output = stderr.split('\n') if stderr else []
        except:
            proc.kill()
            stdout, stderr = proc.communicate()
            stderr_output = stderr.split('\n') if stderr else []
        print("Game terminated")
    
    # Show stderr output
    print("\n" + "="*80)
    print("STDERR OUTPUT (first 50 lines)")
    print("="*80)
    for i, line in enumerate(stderr_output[:50]):
        print(line)
    
    if len(stderr_output) > 50:
        print(f"\n... ({len(stderr_output)} total lines)")
    
    # Check for vblank ticks
    print("\n" + "="*80)
    print("VBLANK TICKS")
    print("="*80)
    vblank_lines = [l for l in stderr_output if 'VBLANK-TICK' in l]
    if vblank_lines:
        print(f"Found {len(vblank_lines)} vblank ticks:")
        for line in vblank_lines[:20]:
            print(f"  {line}")
    else:
        print("No vblank ticks found")
    
    # Analyze the log
    print("\n" + "="*80)
    print("ANALYZING LOG")
    print("="*80)
    
    if not os.path.exists(log_path):
        print(f"ERROR: Log file not found: {log_path}")
        return 1
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        log_content = f.read()
    
    print(f"Log file size: {len(log_content)} bytes")
    print(f"Log file lines: {len(log_content.split(chr(10)))}")
    
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
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())

