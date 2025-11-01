#!/usr/bin/env python3
"""
Test script to run MW05 multiple times to try to reproduce intermittent crash.
Runs the game 10 times for 15 seconds each, logging any crashes.
"""

import subprocess
import sys
import os
import time
from pathlib import Path
from datetime import datetime

def run_single_test(test_num):
    """Run a single test iteration."""
    print(f"\n{'='*60}")
    print(f"TEST #{test_num} - {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    
    # Kill any existing processes
    subprocess.run(["taskkill", "/F", "/IM", "Mw05Recomp.exe"], 
                   capture_output=True, check=False)
    time.sleep(0.5)
    
    # Path to executable
    exe_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe")
    if not exe_path.exists():
        print(f"[ERROR] Executable not found: {exe_path}")
        return False
    
    # MINIMAL environment - NO DEBUG FLAGS
    env = os.environ.copy()
    
    # Remove all MW05_DEBUG_* variables
    keys_to_remove = [k for k in env.keys() if k.startswith("MW05_DEBUG_")]
    for key in keys_to_remove:
        del env[key]
    
    # Remove trace/logging variables
    for key in ["MW05_HOST_TRACE_FILE", "MW05_PM4_TRACE", "MW05_PM4_TRACE_INTERESTING", 
                "MW05_TRACE_KERNEL", "MW05_FILE_LOG"]:
        env.pop(key, None)
    
    # Start the game
    try:
        process = subprocess.Popen(
            [str(exe_path)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        print(f"[START] Game started (PID={process.pid})")
        
        # Wait for process to complete or timeout
        try:
            stdout, stderr = process.communicate(timeout=15)
            
            # Check exit code
            if process.returncode != 0:
                print(f"\n[CRASH] Process exited with code: {process.returncode}")
                print(f"[CRASH] Saving crash logs...")
                
                # Save crash logs
                crash_dir = Path("traces/crashes")
                crash_dir.mkdir(exist_ok=True)
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                crash_file = crash_dir / f"crash_{test_num}_{timestamp}.txt"
                
                with open(crash_file, "w") as f:
                    f.write(f"Test #{test_num}\n")
                    f.write(f"Exit code: {process.returncode}\n")
                    f.write(f"\n{'='*60}\n")
                    f.write("STDERR:\n")
                    f.write(f"{'='*60}\n")
                    f.write(stderr[-5000:] if len(stderr) > 5000 else stderr)
                
                print(f"[CRASH] Logs saved to: {crash_file}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"[SUCCESS] Game ran for 15 seconds without crashing")
            process.kill()
            process.communicate()
            return True
            
    except Exception as e:
        print(f"[ERROR] Failed to start game: {e}")
        return False

def main():
    print("="*60)
    print("MW05 CRASH REPRODUCTION TEST")
    print("="*60)
    print("Running 10 iterations of 15 seconds each...")
    print("Looking for intermittent crashes...")
    
    results = []
    for i in range(1, 11):
        success = run_single_test(i)
        results.append(success)
        time.sleep(1)  # Brief pause between tests
    
    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    crashes = sum(1 for r in results if not r)
    successes = sum(1 for r in results if r)
    
    print(f"Total tests: {len(results)}")
    print(f"Successes: {successes}")
    print(f"Crashes: {crashes}")
    print(f"Crash rate: {crashes/len(results)*100:.1f}%")
    
    if crashes > 0:
        print(f"\n[FOUND] Crash reproduced {crashes} time(s)!")
        print(f"[FOUND] Check traces/crashes/ for crash logs")
        return 1
    else:
        print(f"\n[NOT FOUND] No crashes detected in {len(results)} runs")
        print(f"[INFO] Crash may be very rare or require specific conditions")
        return 0

if __name__ == "__main__":
    sys.exit(main())

