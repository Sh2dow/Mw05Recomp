#!/usr/bin/env python3
"""
Test script to run MW05 with MINIMAL environment variables (no debug flags).
This helps reproduce crashes that only occur without debug mode.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def main():
    # Kill any existing processes
    print("[KILL] Killing existing Mw05Recomp.exe processes...")
    subprocess.run(["taskkill", "/F", "/IM", "Mw05Recomp.exe"], 
                   capture_output=True, check=False)
    time.sleep(0.5)
    
    # Path to executable
    exe_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe")
    if not exe_path.exists():
        print(f"[ERROR] Executable not found: {exe_path}")
        return 1
    
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
    
    print("[START] Starting game with MINIMAL environment (NO DEBUG FLAGS)...")
    print(f"[START] Executable: {exe_path}")
    
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
        
        print(f"[MONITOR] Game started (PID={process.pid})")
        print("[MONITOR] Waiting for crash or 30 seconds...")
        
        # Wait for process to complete or timeout
        try:
            stdout, stderr = process.communicate(timeout=30)
            print(f"\n[EXIT] Process exited with code: {process.returncode}")
            
            if process.returncode != 0:
                print("\n[STDERR]:")
                print(stderr[-2000:] if len(stderr) > 2000 else stderr)
                
        except subprocess.TimeoutExpired:
            print("\n[TIMEOUT] 30 seconds elapsed, killing process...")
            process.kill()
            stdout, stderr = process.communicate()
            print("[SUCCESS] Game ran for 30 seconds without crashing!")
            
    except Exception as e:
        print(f"[ERROR] Failed to start game: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

