#!/usr/bin/env python3
"""Test why video output is stale - only vblank ticks increasing"""

import os
import subprocess
import time
import signal

def main():
    print("="*80)
    print("TESTING STALE VIDEO OUTPUT")
    print("="*80)
    
    # Set environment variables
    env = os.environ.copy()
    env['MW05_FORCE_VIDEO_THREAD'] = '1'
    env['MW05_FORCE_VIDEO_THREAD_TICK'] = '50'
    env['MW05_UNBLOCK_MAIN'] = '1'
    env['MW05_FORCE_PRESENT'] = '1'
    env['MW05_SCHED_R3_EA'] = '0x00060E30'
    env['MW05_TRACE_KERNEL'] = '1'
    
    # Delete old log
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    if os.path.exists(log_path):
        os.remove(log_path)
        print(f"Deleted old log: {log_path}")
    
    # Run the game for 15 seconds
    print("\nStarting game for 15 seconds...")
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    
    stderr_lines = []
    
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
        # Wait for 15 seconds
        time.sleep(15)
    finally:
        # Terminate the process
        print("\nTerminating game...")
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            stdout, stderr = proc.communicate(timeout=5)
            stderr_lines = stderr.split('\n') if stderr else []
        except:
            proc.kill()
            stdout, stderr = proc.communicate()
            stderr_lines = stderr.split('\n') if stderr else []
        print("Game terminated")
    
    # Analyze stderr
    print("\n" + "="*80)
    print("STDERR ANALYSIS")
    print("="*80)
    
    vblank_lines = [l for l in stderr_lines if 'VBLANK-TICK' in l]
    print(f"\nVBLANK ticks: {len(vblank_lines)}")
    if vblank_lines:
        print(f"  First: {vblank_lines[0]}")
        print(f"  Last:  {vblank_lines[-1]}")
    
    # Check for other activity
    non_vblank = [l for l in stderr_lines if l.strip() and 'VBLANK-TICK' not in l]
    print(f"\nNon-VBLANK stderr lines: {len(non_vblank)}")
    if non_vblank:
        print("\nFirst 20 non-VBLANK lines:")
        for line in non_vblank[:20]:
            print(f"  {line}")
    
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
    
    # Check for video thread trigger
    trigger_lines = [l for l in log_lines if 'ForceVideoThread' in l]
    print(f"\nForceVideoThread lines: {len(trigger_lines)}")
    for line in trigger_lines:
        print(f"  {line.rstrip()}")
    
    # Check for sub_82849DE8
    init_lines = [l for l in log_lines if '82849DE8' in l]
    print(f"\nsub_82849DE8 lines: {len(init_lines)}")
    for line in init_lines[:10]:
        print(f"  {line.rstrip()}")
    
    # Check for thread creation
    thread_lines = [l for l in log_lines if 'ExCreateThread' in l or 'Thread.create' in l]
    print(f"\nThread creation lines: {len(thread_lines)}")
    for line in thread_lines:
        print(f"  {line.rstrip()}")
    
    # Check for vblank pump start
    vblank_start = [l for l in log_lines if 'VblankPump.start' in l]
    print(f"\nVblankPump.start lines: {len(vblank_start)}")
    for line in vblank_start:
        print(f"  {line.rstrip()}")
    
    # Check for KeDelayExecutionThread
    delay_lines = [l for l in log_lines if 'KeDelayExecutionThread' in l]
    print(f"\nKeDelayExecutionThread lines: {len(delay_lines)}")
    for line in delay_lines[:5]:
        print(f"  {line.rstrip()}")
    
    # Show last 30 lines of log
    print("\n" + "="*80)
    print("LAST 30 LINES OF LOG")
    print("="*80)
    for line in log_lines[-30:]:
        print(line.rstrip())
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main())

