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
        for backend in ("win32", "uia"):
            for win in Desktop(backend=backend).windows():
                if win.class_name() != "#32770":
                    continue  # only dialog boxes

                # ↓ inside the same loop now!
                try:
                    _, pid = win32process.GetWindowThreadProcessId(win.handle)
                    proc = psutil.Process(pid)
                    pname = proc.name()
                except Exception:
                    continue

                if pname not in TARGET_PROCESSES:
                    continue

                print(f"[MSGBOX] Found dialog: '{win.window_text()}' (pid={pid}, process={pname}, backend={backend})")

                # Try clicking common buttons
                for btn in win.descendants(control_type="Button"):
                    caption = btn.window_text().strip("&").lower()
                    if caption in ["ignore", "ok", "yes", "continue", "retry", "abort"]:
                        print(f"[MSGBOX] Clicking '{caption}' via backend={backend}")
                        btn.click_input()
                        time.sleep(0.3)
                        return True
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
    env = os.environ.copy()

    # Enable debug profile to apply default environment variables
    env["MW05_DEBUG_PROFILE"] = "1"

    # Set all environment variables from run_with_env.cmd
    env["MW05_HOST_TRACE_FILE"] = "mw05_host_trace.log"
    env["MW05_TRACE_KERNEL"] = "1"

    # env["MW05_BREAK_82813514"] = "0"
    # env["MW05_FAKE_ALLOC_SYSBUF"] = "1"
    # env["MW05_UNBLOCK_MAIN"] = "0"
    # env["MW05_HOST_TRACE_IMPORTS"] = "1"
    # env["MW05_HOST_TRACE_HOSTOPS"] = "1"
    # env["MW05_TRACE_HEAP"] = "1"
    # env["MW05_BREAK_SLEEP_LOOP"] = "1"
    # env["MW05_BREAK_SLEEP_AFTER"] = "5"
    # 
    # env["MW05_VBLANK_VDSWAP"] = "0"
    # env["MW05_KICK_VIDEO"] = "0"
    # env["MW05_VDSWAP_NOTIFY"] = "0"
    # env["MW05_FAST_BOOT"] = "0"
    # env["MW05_FAST_RET"] = "0"
    # env["MW05_FORCE_VD_INIT"] = "1"
    # 
    # env["MW05_TRACE_INDIRECT"] = "0"
    # env["MW05_TITLE_STATE_TRACE"] = "1"
    # env["MW05_BREAK_WAIT_LOOP"] = "0"
    # env["MW05_FORCE_VIDEO_THREAD"] = "0"
    # env["MW05_FORCE_VIDEO_THREAD_TICK"] = "0"
    # env["MW05_DEFAULT_VD_ISR"] = "0"
    # env["MW05_REGISTER_DEFAULT_VD_ISR"] = "0"
    # env["MW05_PULSE_VD_ON_SLEEP"] = "0"
    # env["MW05_PRESENT_HEARTBEAT_MS"] = "0"
    # 
    # env["MW05_STREAM_BRIDGE"] = "1"
    # env["MW05_STREAM_FALLBACK_BOOT"] = "1"
    # env["MW05_STREAM_ACK_NO_PATH"] = "0"
    # env["MW05_LOOP_TRY_PM4_PRE"] = "0"
    # env["MW05_LOOP_TRY_PM4_POST"] = "0"
    # env["MW05_INNER_TRY_PM4"] = "0"
    # env["MW05_FORCE_GFX_NOTIFY_CB"] = "1"
    # env["MW05_FORCE_GFX_NOTIFY_CB_CTX"] = "0x40007180"
    # env["MW05_FORCE_GFX_NOTIFY_CB_DELAY_TICKS"] = "350"
    # env["MW05_VD_ISR_SWAP_PARAMS"] = "0"
    # 
    # env["MW05_FORCE_PRESENT"] = "1"
    # env["MW05_FORCE_PRESENT_BG"] = "1"
    # env["MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS"] = "0"
    # env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "1"
    # env["MW05_FORCE_PRESENT_EVERY_ZERO"] = "1"
    # env["MW05_FORCE_PRESENT_ON_ZERO"] = "1"
    # env["MW05_FORCE_PRESENT_ON_FIRST_ZERO"] = "1"
    # 
    # env["MW05_SCHED_R3_EA"] = "0x00260370"
    # env["MW05_FPW_KICK_PM4"] = "1"
    # 
    # # DISABLE force-call workarounds - let the game initialize naturally via worker threads!
    # # The worker threads (created by MW05_FORCE_RENDER_THREADS=1) will call the initialization chain:
    # # Thread 0x828508A8 -> callback 0x8261A558 -> work_func 0x82441E58 -> sub_823B0190 -> sub_823AF590 -> ... -> sub_825A16A0
    # env["MW05_FORCE_CALL_CREATEDEVICE"] = "0"
    # env["MW05_FORCE_CREATEDEVICE_DELAY_TICKS"] = "400"  # Not used when disabled
    # 
    # env["MW05_FORCE_CALL_CREATE_RENDER_THREAD"] = "0"
    # env["MW05_FORCE_CREATE_RENDER_THREAD_DELAY_TICKS"] = "500"  # Not used when disabled
    # 
    # # CRITICAL FIX: Force-initialize the callback parameter structure and create worker threads!
    # # The worker threads call work_func (0x82441E58) which initializes the entire game!
    # # Without this, sub_823B0190 -> sub_823AF590 -> sub_82216088 -> ... -> sub_825A16A0 is NEVER called!
    # # This is why offset+20576 remains 0x00000000 instead of 0x04000001!
    # env["MW05_FORCE_INIT_CALLBACK_PARAM"] = "1"  # Initialize callback parameter structure
    # env["MW05_FORCE_RENDER_THREADS"] = "0"  # Disable the render thread creation (wrong threads)
    # env["MW05_FORCE_RENDER_THREAD"] = "0"  # Keep this disabled - it's for a different thread
    # 
    # # Signal the VD interrupt event to wake up the render thread
    # env["MW05_HOST_ISR_SIGNAL_VD_EVENT"] = "1"
    # env["MW05_PULSE_VD_EVENT_ON_SLEEP"] = "1"
    # 
    # # Enable PM4 state application
    # env["MW05_PM4_APPLY_STATE"] = "1"
    # 
    # # Force the flag at r31+10434 that gates present calls
    # env["MW05_FORCE_PRESENT_FLAG"] = "1"
    # 
    # # CRITICAL: Enable present callback pointer workaround
    # env["MW05_SET_PRESENT_CB"] = "1"

    print("Environment variables (MINIMAL - NO WORKAROUNDS):")
    for key in sorted(env.keys()):
        if key.startswith("MW05_"):
            print(f"  {key} = {env[key]}")
            
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

    # Analyze trace log
    trace_log = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    if trace_log.exists():
        log_size_mb = trace_log.stat().st_size / (1024 * 1024)
        print(f"\n[TRACE] Log size: {log_size_mb:.2f} MB")

        with open(trace_log, "r", encoding="utf-8", errors="ignore") as f:
            # Read last 10000 lines for analysis
            lines = f.readlines()
            tail_lines = lines[-10000:] if len(lines) > 10000 else lines

            # Check for heap allocation
            heap_lines = [l for l in tail_lines if "Heap Allocated:" in l]
            if heap_lines:
                print(f"[HEAP] {heap_lines[-1].strip()}")

            # Check for draws
            draw_lines = [l for l in tail_lines if "draws=" in l]
            if draw_lines:
                last_draw = draw_lines[-1].strip()
                print(f"[DRAWS] {last_draw}")

            # Check for sleep function calls
            sleep_calls = len([l for l in tail_lines if "sub_8262D9D0" in l])
            print(f"[SLEEP] sub_8262D9D0 calls in last 10k lines: {sleep_calls}")

            # Check for main loop flag setting
            flag_sets = len([l for l in tail_lines if "set_main_loop_flag" in l])
            print(f"[FLAG] Main loop flag sets: {flag_sets}")

            # Check for PM4 commands
            pm4_lines = [l for l in tail_lines if "PM4.Scan" in l]
            print(f"[PM4] PM4 scan operations: {len(pm4_lines)}")

            # Check for VdSwap calls
            vdswap_lines = [l for l in tail_lines if "VdSwap" in l]
            print(f"[VDSWAP] VdSwap calls: {len(vdswap_lines)}")

            # Check for Present calls
            present_lines = [l for l in tail_lines if "PRESENT" in l]
            print(f"[PRESENT] Present calls: {len(present_lines)}")

    # Show last 30 lines of stderr
    if stderr_file.exists():
        with open(stderr_file, "r") as f:
            lines = f.readlines()
        print(f"\n[STDERR] Last 30 lines:")
        for line in lines[-30:]:
            print(f"  {line.rstrip()}")

    return process.returncode if process.returncode is not None else 0

if __name__ == "__main__":
    sys.exit(main())

