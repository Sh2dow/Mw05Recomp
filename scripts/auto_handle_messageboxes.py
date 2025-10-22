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
from pywinauto import Desktop
import psutil
import win32process

# Add pywinauto to path if needed
try:
    import pywinauto
    from pywinauto import Application
    from pywinauto.findwindows import find_windows
except ImportError:
    print("ERROR: pywinauto not installed. Install with: pip install pywinauto")
    sys.exit(1)


TARGET_PROCESSES = ["Mw05Recomp.exe"]

def find_and_click_messagebox():
    try:
        for win in Desktop(backend="win32").windows():
            if win.class_name() != "#32770":
                continue  # only dialog boxes

            # Get process name
            try:
                _, pid = win32process.GetWindowThreadProcessId(win.handle)
                proc = psutil.Process(pid)
                pname = proc.name()
            except Exception:
                continue

            # Skip if not our game
            if pname not in TARGET_PROCESSES:
                continue

            print(f"[MSGBOX] Found dialog: '{win.window_text()}' (pid={pid}, process={pname})")

            # Try clicking common buttons
            for btn_title in ["Ignore", "Abort", "OK", "Yes", "Continue", "Retry"]:
                try:
                    btn = win.child_window(title=btn_title, control_type="Button")
                    if btn.exists():
                        print(f"[MSGBOX] Clicking '{btn_title}'")
                        btn.click()
                        time.sleep(0.5)
                        return True
                except Exception:
                    continue

    except Exception as e:
        print(f"[WARN] Exception in find_and_click_messagebox: {e}")
    return False

def main():
    """Run game and auto-handle messageboxes."""

    # Parse command-line arguments
    import argparse
    parser = argparse.ArgumentParser(description="Run game and auto-handle messageboxes")
    parser.add_argument("--duration", type=int, default=60, help="Duration to run game in seconds (default: 60)")
    args = parser.parse_args()

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
    print(f"[START] Will run for {args.duration} seconds and auto-handle any messageboxes...")

    # ENVIRONMENT VARIABLES - EXACT COPY from run_with_env.cmd
    # These are CRITICAL for the game to progress past initialization
    env = os.environ.copy()
    env["MW05_DEBUG_PROFILE"] = "1"
    env["MW05_HOST_TRACE_FILE"] = "mw05_host_trace.log"
    env["MW05_BREAK_82813514"] = "0"
    env["MW05_FAKE_ALLOC_SYSBUF"] = "1"
    env["MW05_UNBLOCK_MAIN"] = "1"
    env["MW05_TRACE_KERNEL"] = "1"
    env["MW05_HOST_TRACE_IMPORTS"] = "1"
    env["MW05_HOST_TRACE_HOSTOPS"] = "1"
    env["MW05_TRACE_HEAP"] = "1"
    env["MW05_BREAK_SLEEP_LOOP"] = "1"
    env["MW05_BREAK_SLEEP_AFTER"] = "5"

    env["MW05_VBLANK_VDSWAP"] = "0"
    env["MW05_KICK_VIDEO"] = "0"
    env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "0"
    env["MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS"] = "0"
    env["MW05_FORCE_PRESENT"] = "0"
    env["MW05_FORCE_PRESENT_BG"] = "0"
    env["MW05_VDSWAP_NOTIFY"] = "0"
    env["MW05_FAST_BOOT"] = "0"
    env["MW05_FAST_RET"] = "0"
    env["MW05_FORCE_VD_INIT"] = "1"
    env["MW05_TRACE_INDIRECT"] = "0"
    env["MW05_TITLE_STATE_TRACE"] = "1"
    env["MW05_BREAK_WAIT_LOOP"] = "0"
    env["MW05_FORCE_VIDEO_THREAD"] = "0"
    env["MW05_FORCE_VIDEO_THREAD_TICK"] = "0"
    env["MW05_DEFAULT_VD_ISR"] = "0"
    env["MW05_REGISTER_DEFAULT_VD_ISR"] = "0"
    env["MW05_PULSE_VD_ON_SLEEP"] = "0"
    env["MW05_PRESENT_HEARTBEAT_MS"] = "0"
    env["MW05_STREAM_BRIDGE"] = "1"
    env["MW05_STREAM_FALLBACK_BOOT"] = "1"
    env["MW05_STREAM_ACK_NO_PATH"] = "0"
    env["MW05_LOOP_TRY_PM4_PRE"] = "0"
    env["MW05_LOOP_TRY_PM4_POST"] = "0"
    env["MW05_INNER_TRY_PM4"] = "0"
    env["MW05_FORCE_GFX_NOTIFY_CB"] = "1"
    env["MW05_FORCE_GFX_NOTIFY_CB_CTX"] = "0x40007180"
    env["MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS"] = "350"
    env["MW05_SET_PRESENT_CB"] = "1"
    env["MW05_VD_ISR_SWAP_PARAMS"] = "0"
    env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "1"
    env["MW05_FORCE_PRESENT_EVERY_ZERO"] = "1"
    env["MW05_FORCE_PRESENT_ON_ZERO"] = "1"
    env["MW05_FORCE_PRESENT_ON_FIRST_ZERO"] = "1"

    env["MW05_SCHED_R3_EA"] = "0x00260370"
    env["MW05_FPW_KICK_PM4"] = "1"

    # Force-create the render threads that issue draw commands
    env["MW05_FORCE_RENDER_THREADS"] = "1"

    # CRITICAL: Force initialization of callback parameter structure
    # This is required for worker threads to start processing work items
    env["MW05_FORCE_INIT_CALLBACK_PARAM"] = "1"

    # Signal the VD interrupt event to wake up the render thread
    env["MW05_HOST_ISR_SIGNAL_VD_EVENT"] = "1"
    env["MW05_PULSE_VD_EVENT_ON_SLEEP"] = "1"

    # Enable PM4 state application
    env["MW05_PM4_APPLY_STATE"] = "1"

    # Force the flag at r31+10434 that gates present calls
    env["MW05_FORCE_PRESENT_FLAG"] = "1"

    print(f"[ENV] Running with ALL environment variables from run_with_env.cmd + MW05_FORCE_INIT_CALLBACK_PARAM")

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
            bufsize=1,
            env=env  # Pass environment variables to subprocess
        )

        start_time = time.time()
        duration = args.duration  # Run for specified duration
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

