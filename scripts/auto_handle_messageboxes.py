#!/usr/bin/env python3
"""
Auto-handle all messageboxes that appear during game execution.
Detects and clicks "Ignore" button on any messagebox.
"""

import subprocess
import time
import sys
import os
from pathlib import Path

# Add pywinauto to path if needed
try:
    import pywinauto
    from pywinauto import Application
    from pywinauto.findwindows import find_windows
except ImportError:
    print("ERROR: pywinauto not installed. Install with: pip install pywinauto")
    sys.exit(1)

def find_and_click_messagebox():
    """Find any messagebox and click Ignore/OK button."""
    try:
        # Find all windows with common messagebox titles
        messagebox_titles = [
            "Mw05 Recompiled",
            "Microsoft Visual C++ Runtime Library",
            "Debug Error",
            "Error",
            "Assertion Failed"
        ]
        
        for title in messagebox_titles:
            try:
                windows = find_windows(title_re=f".*{title}.*")
                if windows:
                    print(f"[MSGBOX] Found messagebox with title containing '{title}'")
                    for hwnd in windows:
                        try:
                            app = Application().connect(handle=hwnd)
                            dlg = app.window(handle=hwnd)
                            
                            # Try to click Ignore button first
                            try:
                                ignore_btn = dlg.child_window(title="Ignore", control_type="Button")
                                if ignore_btn.exists():
                                    print(f"[MSGBOX] Clicking 'Ignore' button")
                                    ignore_btn.click()
                                    time.sleep(0.5)
                                    return True
                            except:
                                pass
                            
                            # Try to click OK button
                            try:
                                ok_btn = dlg.child_window(title="OK", control_type="Button")
                                if ok_btn.exists():
                                    print(f"[MSGBOX] Clicking 'OK' button")
                                    ok_btn.click()
                                    time.sleep(0.5)
                                    return True
                            except:
                                pass
                            
                            # Try to click Retry button (will retry the operation)
                            try:
                                retry_btn = dlg.child_window(title="Retry", control_type="Button")
                                if retry_btn.exists():
                                    print(f"[MSGBOX] Clicking 'Retry' button")
                                    retry_btn.click()
                                    time.sleep(0.5)
                                    return True
                            except:
                                pass
                                
                        except Exception as e:
                            pass
            except:
                pass
                
    except Exception as e:
        pass
    
    return False

def main():
    """Run game and auto-handle messageboxes."""
    
    # Kill any existing Mw05Recomp processes
    print("[KILL] Killing existing Mw05Recomp.exe processes...")
    subprocess.run(["taskkill", "/F", "/IM", "Mw05Recomp.exe"], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Start the game
    exe_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/Mw05Recomp.exe")
    if not exe_path.exists():
        print(f"[ERROR] Game executable not found: {exe_path}")
        sys.exit(1)
    
    print(f"[START] Starting game: {exe_path}")
    print("[START] Will run for 60 seconds and auto-handle any messageboxes...")
    
    # Redirect stderr to file directly (game writes to stderr in real-time)
    stderr_file = Path("traces/auto_test_stderr.txt")
    stdout_file = Path("traces/auto_test_stdout.txt")

    with open(stderr_file, "w") as stderr_f, open(stdout_file, "w") as stdout_f:
        # Start game process (don't wait for it to finish)
        process = subprocess.Popen(
            [str(exe_path)],
            stdout=stdout_f,
            stderr=stderr_f,
            text=True,
            bufsize=1
        )
    
        start_time = time.time()
        duration = 60  # Run for 60 seconds
        check_interval = 0.5  # Check for messageboxes every 0.5 seconds

        print(f"[MONITOR] Monitoring for messageboxes (PID={process.pid})...")

        while True:
            elapsed = time.time() - start_time

            # Check if process is still running
            if process.poll() is not None:
                print(f"[EXIT] Game exited with code {process.returncode} after {elapsed:.1f}s")
                break

            # Check if duration exceeded
            if elapsed >= duration:
                print(f"[TIMEOUT] Reached {duration}s timeout, terminating game...")
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
                break

            # Check for messageboxes
            if find_and_click_messagebox():
                print(f"[MSGBOX] Handled messagebox at {elapsed:.1f}s")

            # Read any available output (non-blocking)
            try:
                # This is a simple approach - in production you'd use select/threading
                time.sleep(check_interval)
            except KeyboardInterrupt:
                print(f"\n[INTERRUPT] User interrupted, terminating game...")
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
                break

    print(f"\n[DONE] Output saved to:")
    print(f"  stdout: {stdout_file}")
    print(f"  stderr: {stderr_file}")

    # Show last 50 lines of stderr
    if stderr_file.exists():
        with open(stderr_file, "r") as f:
            lines = f.readlines()
        print(f"\n[STDERR] Last 50 lines:")
        for line in lines[-50:]:
            print(f"  {line.rstrip()}")
    
    return process.returncode if process.returncode is not None else 0

if __name__ == "__main__":
    sys.exit(main())

