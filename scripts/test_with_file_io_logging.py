#!/usr/bin/env python3
"""
Test script to run MW05 with file I/O logging enabled.
This will help us see if the loader is actually loading files.
"""

import subprocess
import sys
import os
import time
from pathlib import Path

def main():
    print("="*60)
    print("MW05 FILE I/O LOGGING TEST")
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
    
    # Set environment variables for file I/O logging
    env = os.environ.copy()
    
    # Enable file I/O logging
    env["MW05_FILE_LOG"] = "1"
    env["MW05_DEBUG_FILEIO"] = "2"
    
    # Enable kernel tracing to see file operations
    env["MW05_TRACE_KERNEL"] = "1"
    env["MW05_HOST_TRACE_FILE"] = "mw05_host_trace.log"
    
    # Enable basic debugging
    env["MW05_DEBUG_PROFILE"] = "1"
    
    # Disable verbose logging to reduce noise
    env["MW05_PM4_TRACE"] = "0"
    env["MW05_PM4_TRACE_INTERESTING"] = "0"
    
    print("\nEnvironment variables:")
    print("  MW05_FILE_LOG=1")
    print("  MW05_DEBUG_FILEIO=2")
    print("  MW05_TRACE_KERNEL=1")
    print("  MW05_HOST_TRACE_FILE=mw05_host_trace.log")
    
    # Start the game
    try:
        print(f"\n[START] Starting game for 60 seconds...")
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
            stdout, stderr = process.communicate(timeout=60)
            
            # Save output
            stderr_file = Path("traces/file_io_test_stderr.txt")
            stderr_file.parent.mkdir(exist_ok=True)
            stderr_file.write_text(stderr)
            
            print(f"\n[DONE] Game exited with code: {process.returncode}")
            print(f"[DONE] Stderr saved to: {stderr_file}")
            
        except subprocess.TimeoutExpired:
            print(f"\n[TIMEOUT] 60 seconds elapsed, stopping game...")
            process.kill()
            stdout, stderr = process.communicate()
            
            # Save output
            stderr_file = Path("traces/file_io_test_stderr.txt")
            stderr_file.parent.mkdir(exist_ok=True)
            stderr_file.write_text(stderr)
            
            print(f"[DONE] Stderr saved to: {stderr_file}")
            
    except Exception as e:
        print(f"[ERROR] Failed to start game: {e}")
        return 1
    
    # Analyze the output
    print("\n" + "="*60)
    print("ANALYZING FILE I/O OPERATIONS")
    print("="*60)
    
    stderr_file = Path("traces/file_io_test_stderr.txt")
    if stderr_file.exists():
        content = stderr_file.read_text()
        
        # Count file I/O operations
        file_io_patterns = {
            "NtCreateFile": content.count("NtCreateFile"),
            "NtOpenFile": content.count("NtOpenFile"),
            "NtReadFile": content.count("NtReadFile"),
            "NtWriteFile": content.count("NtWriteFile"),
            "NtClose": content.count("NtClose"),
        }
        
        print("\nFile I/O operation counts:")
        for op, count in file_io_patterns.items():
            print(f"  {op}: {count}")
        
        total_file_ops = sum(file_io_patterns.values())
        print(f"\nTotal file I/O operations: {total_file_ops}")
        
        if total_file_ops == 0:
            print("\n[WARNING] NO FILE I/O OPERATIONS DETECTED!")
            print("[WARNING] This suggests the loader is not actually loading files.")
        else:
            print("\n[SUCCESS] File I/O operations detected!")
            print("[SUCCESS] Loader appears to be working.")
            
            # Show sample file operations
            print("\nSample file operations:")
            lines = content.split('\n')
            file_io_lines = [line for line in lines if any(op in line for op in file_io_patterns.keys())]
            for line in file_io_lines[:20]:
                print(f"  {line}")
    
    # Check for draws
    print("\n" + "="*60)
    print("CHECKING FOR DRAW COMMANDS")
    print("="*60)
    
    if stderr_file.exists():
        content = stderr_file.read_text()
        
        # Look for draw count
        import re
        draw_matches = re.findall(r'draws=(\d+)', content)
        if draw_matches:
            final_draws = draw_matches[-1]
            print(f"\nFinal draw count: {final_draws}")
            
            if int(final_draws) > 0:
                print("[SUCCESS] DRAWS DETECTED! Game is rendering!")
            else:
                print("[INFO] Still draws=0, game not rendering yet")
        else:
            print("[INFO] No draw count found in logs")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

