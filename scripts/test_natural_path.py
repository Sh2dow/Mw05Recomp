#!/usr/bin/env python3
"""
Test MW05 with MINIMAL environment variables to see the natural initialization path.
This removes all the workarounds to see what actually happens naturally.
"""

import subprocess
import sys
import os
import time
import threading

def run_test():
    """Run MW05 with minimal environment variables."""
    
    exe_path = r"D:\Repos\Games\Mw05Recomp\out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe"
    
    if not os.path.exists(exe_path):
        print(f"ERROR: Executable not found at {exe_path}")
        return 1
    
    # Kill any existing instances
    try:
        subprocess.run(["taskkill", "/F", "/IM", "Mw05Recomp.exe"], 
                      capture_output=True, timeout=5)
        time.sleep(1)
    except:
        pass
    
    # Set MINIMAL environment variables - only essential ones, NO WORKAROUNDS!
    env = os.environ.copy()
    
    # Basic tracing only
    env["MW05_HOST_TRACE_FILE"] = "traces/natural_path_trace.log"
    env["MW05_TRACE_KERNEL"] = "1"
    
    print("=" * 80)
    print("TESTING NATURAL INITIALIZATION PATH - NO WORKAROUNDS!")
    print("=" * 80)
    print(f"Executable: {exe_path}")
    print(f"Trace file: traces/natural_path_trace.log")
    print(f"Stderr: traces/natural_path_stderr.txt")
    print()
    print("Environment variables (MINIMAL - NO WORKAROUNDS):")
    for key in sorted(env.keys()):
        if key.startswith("MW05_"):
            print(f"  {key} = {env[key]}")
    print()
    print("Running for 60 seconds to observe natural behavior...")
    print("=" * 80)
    
    # Create traces directory
    os.makedirs("traces", exist_ok=True)
    
    # Run the process
    with open("traces/natural_path_stderr.txt", "w") as stderr_file:
        proc = subprocess.Popen(
            [exe_path],
            env=env,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            cwd=os.path.dirname(exe_path)
        )
        
        try:
            # Wait for 60 seconds
            proc.wait(timeout=60)
            print(f"\nProcess exited with code: {proc.returncode}")
        except subprocess.TimeoutExpired:
            print("\n60 seconds elapsed, terminating process...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print("Force killing process...")
                proc.kill()
                proc.wait()
    
    print("\n" + "=" * 80)
    print("TEST COMPLETE - Check traces/natural_path_stderr.txt for results")
    print("=" * 80)
    
    # Show last 50 lines of stderr
    print("\nLast 50 lines of stderr:")
    print("-" * 80)
    try:
        with open("traces/natural_path_stderr.txt", "r") as f:
            lines = f.readlines()
            for line in lines[-50:]:
                print(line.rstrip())
    except Exception as e:
        print(f"Error reading stderr: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(run_test())

