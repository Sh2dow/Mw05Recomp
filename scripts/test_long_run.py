#!/usr/bin/env python3
"""
Long-running test to see if draws eventually appear.
Captures both stdout and stderr to see file loading activity.
"""

import subprocess
import sys
import os
import time
from pathlib import Path
from datetime import datetime

def main():
    print("="*60)
    print("MW05 LONG RUN TEST (120 seconds)")
    print("="*60)
    
    # Kill any existing processes
    subprocess.run(["taskkill", "/F", "/IM", "Mw05Recomp.exe"], 
                   capture_output=True, check=False)
    time.sleep(0.5)
    
    # Path to executable
    exe_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe")
    if not exe_path.exists():
        print(f"[ERROR] Executable not found: {exe_path}")
        return 1
    
    # Set environment variables
    env = os.environ.copy()
    
    # Enable tracing to see file I/O in stdout
    env["MW05_HOST_TRACE_FILE"] = "mw05_host_trace.log"
    env["MW05_HOST_TRACE_HOSTOPS"] = "1"
    env["MW05_HOST_TRACE_IMPORTS"] = "1"
    
    # Enable basic debugging
    env["MW05_DEBUG_PROFILE"] = "1"
    env["MW05_PM4_TRACE"] = "1"
    
    print("\nEnvironment variables:")
    print("  MW05_HOST_TRACE_FILE=mw05_host_trace.log")
    print("  MW05_HOST_TRACE_HOSTOPS=1")
    print("  MW05_HOST_TRACE_IMPORTS=1")
    print("  MW05_DEBUG_PROFILE=1")
    print("  MW05_PM4_TRACE=1")
    
    # Start the game
    try:
        print(f"\n[START] Starting game for 120 seconds...")
        start_time = time.time()
        
        process = subprocess.Popen(
            [str(exe_path)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        print(f"[START] Game started (PID={process.pid})")
        
        # Monitor for draws in real-time
        last_draw_check = time.time()
        last_draws = 0
        
        # Wait for process to complete or timeout
        try:
            stdout, stderr = process.communicate(timeout=120)
            
            # Save output
            stdout_file = Path("traces/long_run_stdout.txt")
            stderr_file = Path("traces/long_run_stderr.txt")
            stdout_file.parent.mkdir(exist_ok=True)
            
            stdout_file.write_text(stdout)
            stderr_file.write_text(stderr)
            
            print(f"\n[DONE] Game exited with code: {process.returncode}")
            print(f"[DONE] Stdout saved to: {stdout_file}")
            print(f"[DONE] Stderr saved to: {stderr_file}")
            
        except subprocess.TimeoutExpired:
            print(f"\n[TIMEOUT] 120 seconds elapsed, stopping game...")
            process.kill()
            stdout, stderr = process.communicate()
            
            # Save output
            stdout_file = Path("traces/long_run_stdout.txt")
            stderr_file = Path("traces/long_run_stderr.txt")
            stdout_file.parent.mkdir(exist_ok=True)
            
            stdout_file.write_text(stdout)
            stderr_file.write_text(stderr)
            
            print(f"[DONE] Stdout saved to: {stdout_file}")
            print(f"[DONE] Stderr saved to: {stderr_file}")
            
    except Exception as e:
        print(f"[ERROR] Failed to start game: {e}")
        return 1
    
    # Analyze the output
    print("\n" + "="*60)
    print("ANALYZING RESULTS")
    print("="*60)
    
    # Check for file I/O in stdout
    stdout_file = Path("traces/long_run_stdout.txt")
    if stdout_file.exists():
        content = stdout_file.read_text()
        
        file_count = content.count("StreamBridge")
        print(f"\nFile I/O operations (StreamBridge): {file_count}")
        
        if file_count > 0:
            print("\nSample file operations:")
            lines = content.split('\n')
            file_lines = [line for line in lines if "StreamBridge" in line]
            for line in file_lines[:10]:
                print(f"  {line}")
    
    # Check for draws in stderr
    stderr_file = Path("traces/long_run_stderr.txt")
    if stderr_file.exists():
        content = stderr_file.read_text()
        
        import re
        draw_matches = re.findall(r'draws=(\d+)', content)
        if draw_matches:
            final_draws = draw_matches[-1]
            print(f"\nFinal draw count: {final_draws}")
            
            if int(final_draws) > 0:
                print("\n" + "="*60)
                print("🎉 SUCCESS! DRAWS DETECTED! GAME IS RENDERING!")
                print("="*60)
            else:
                print("\n[INFO] Still draws=0 after 120 seconds")
                print("[INFO] Game may need more time or there's a blocking issue")
        else:
            print("\n[INFO] No draw count found in logs")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

