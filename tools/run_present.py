#!/usr/bin/env python3
# Lightweight, robust diagnostic runner for Mw05Recomp.
# - Hard timeout watchdog
# - Optional early-exit on first draw
# - Minimal file I/O (tail-only) and safe cleanup
# - No external dependencies

import argparse
import os
import sys
import time
import subprocess
import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PRESET = "x64-Clang-Debug"
DEFAULT_BUILD_DIR = REPO_ROOT / "out" / "build" / DEFAULT_PRESET / "Mw05Recomp"
DEFAULT_EXE = DEFAULT_BUILD_DIR / "Mw05Recomp.exe"
DEFAULT_LOG = DEFAULT_BUILD_DIR / "mw05_host_trace.log"
DEFAULT_SUMMARY = DEFAULT_BUILD_DIR / "mw05_run_summary.txt"

import re

def tail_has_draw(path: Path, max_lines: int = 800) -> bool:
    """Return True only if we see concrete PM4 draw evidence (draws > 0).

    Heuristics:
    - Any explicit HOST.PM4.DRAW_* marker
    - SysBufDrawCount with a positive number (parsed)
    - ScanAllOnPresent with draws > 0 (parsed)
    """
    try:
        if not path.exists():
            return False
        # Read last N lines cheaply
        with path.open('rb') as f:
            f.seek(0, os.SEEK_END)
            block = 8192
            data = b''
            while len(data.splitlines()) <= max_lines and f.tell() > 0:
                seek = max(0, f.tell() - block)
                f.seek(seek)
                data = f.read(min(block, f.tell())) + data
                f.seek(seek)
                if seek == 0:
                    break
        text = data.decode(errors='ignore')
        # 1) Definitive: any TYPE3 draw packet parsed by PM4 layer
        if "HOST.PM4.DRAW_" in text:
            return True
        # 2) Parsed counters that must be > 0
        for line in reversed(text.splitlines()):
            if "HOST.PM4.SysBufDrawCount" in line:
                m = re.search(r"SysBufDrawCount=([0-9]+)", line)
                if m and int(m.group(1)) > 0:
                    return True
            if "HOST.PM4.ScanAllOnPresent" in line:
                m = re.search(r"draws=([0-9]+)", line)
                if m and int(m.group(1)) > 0:
                    return True
        return False
    except Exception:
        return False


def write_summary(summary_path: Path, d: dict):
    try:
        lines = [f"{k}={v}" for k, v in d.items()]
        summary_path.write_text("\n".join(lines), encoding='utf-8')
    except Exception:
        pass


def build_env(from_parent: bool, until_draw: bool, draw_diag: bool, strict: bool = False, pm4_le: str | None = None) -> dict:
    env = dict(os.environ if from_parent else {})
    # Ensure key PM4/Micro tracing and state mirroring are enabled by default
    env.setdefault("MW05_PM4_APPLY_STATE", "1")
    env.setdefault("MW05_PM4_LOG_NONZERO", "1")
    env.setdefault("MW05_MICRO_TREE", "1")
    # Baseline diagnostics and safe defaults
    env.setdefault("MW05_TRACE_INDIRECT", "1")
    env.setdefault("MW05_TRACE_KERNEL", "1")
    env.setdefault("MW05_HOST_TRACE_IMPORTS", "0")
    env.setdefault("MW05_HOST_TRACE_HOSTOPS", "1")
    # Also enable file logging for indirect-miss extraction
    env.setdefault("MW05_LOG_FILE", str(DEFAULT_BUILD_DIR / "mw05_debug.log"))
    env.setdefault("MW05_PM4_SYSBUF_TO_RING", "0")
    env.setdefault("MW05_DISABLE_OVERRIDES", "0")
    env.setdefault("MW05_RUNTIME_PATCHES", "0")
    env.setdefault("MW05_PM4_SWAP_PRESENT", "1")
    env.setdefault("MW05_VDSWAP_NOTIFY", "1")
    env.setdefault("MW05_FORCE_VD_INIT", "1")
    env.setdefault("MW05_VD_POLL_DIAG", "1")
    env.setdefault("MW05_PRESENT_HEARTBEAT_MS", "250")
    env.setdefault("MW05_FORCE_PRESENT", "0")
    env.setdefault("MW05_FORCE_PRESENT_BG", "0")
    env.setdefault("MW05_SYNTH_VDSWAP_ON_FLIP", "0")
    env.setdefault("MW05_FORCE_VDSWAP_ONCE", "0")
    env.setdefault("MW05_VDSWAP_ACK", "1")
    env.setdefault("MW05_REGISTER_DEFAULT_VD_ISR", "1")
    env.setdefault("MW05_DEFAULT_VD_ISR", "1")
    env.setdefault("MW05_PUMP_EVENTS", "1")
    env.setdefault("MW05_HOST_ISR_TICK_SYSID", "1")
    # Force-register known-good graphics notify ISR from Xenia capture (safe if guest sets it later)
    env.setdefault("MW05_FORCE_GFX_NOTIFY_CB", "1")
    env.setdefault("MW05_FORCE_GFX_NOTIFY_CB_EA", "0x825979A8")
    env.setdefault("MW05_FORCE_GFX_NOTIFY_CB_CTX", "1")

    env.setdefault("MW05_PM4_SYSBUF_WATCH", "1")
    # Heuristics to advance pre-swap state machines some titles expect
    env.setdefault("MW05_VD_TICK_E70", "1")
    env.setdefault("MW05_VD_TOGGLE_E68", "1")
    # Seed VdSwap heuristics to help titles that wait on e58/e68 progress/ack
    env.setdefault("MW05_AUTO_VDSWAP_HEUR", "1")
    env.setdefault("MW05_AUTO_VDSWAP_HEUR_DELAY", "2")
    env.setdefault("MW05_AUTO_VDSWAP_HEUR_ONCE", "1")
    env.setdefault("MW05_AUTO_VDSWAP_HEUR_E58_MASK", "0")
    env.setdefault("MW05_AUTO_VDSWAP_HEUR_E68_MASK", "0x2")
    # Optionally keep ack bit asserted to satisfy heuristics preconditions
    env.setdefault("MW05_PM4_FAKE_SWAP", "0")
    # Aggressive nudge to progress pre-swap and present paths when stuck
    env["MW05_PM4_FAKE_SWAP"] = "1"          # keep ACK bit asserted (safe pre-render)
    env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "1"
    env["MW05_FORCE_PRESENT"] = "1"
    env["MW05_FORCE_PRESENT_BG"] = "1"
    env["MW05_SYNTH_VDSWAP_ONCE"] = "1"
    # Allow toggles to be overridden for strict mode after defaults are set
    if strict:
        # Disable aggressive present/swap nudges
        env["MW05_PM4_FAKE_SWAP"] = "0"
        env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "0"
        env["MW05_FORCE_PRESENT"] = "0"
        env["MW05_FORCE_PRESENT_BG"] = "0"
        env["MW05_SYNTH_VDSWAP_ONCE"] = "0"
        # Keep ISR visibility but avoid forcing ctx if running draw_diag strict
        env["MW05_FORCE_GFX_NOTIFY_CB_CTX"] = "0"
        # Avoid mutating WAITs or bridging syscmd into ring artificially
        env["MW05_PM4_BYPASS_WAITS"] = "0"
        env["MW05_PM4_SYSBUF_TO_RING"] = "0"


    env.setdefault("MW05_PM4_FAKE_SWAP_ADDR", "0x00060E68")
    env.setdefault("MW05_PM4_FAKE_SWAP_OR", "0x2")
    # Nudge swap path for titles that never call VdSwap early
    env.setdefault("MW05_SYNTH_VDSWAP_ON_FLIP", "0")
    env.setdefault("MW05_FORCE_VDSWAP_ONCE", "0")
    # Nudge present-wrapper once after a short grace period, only if a valid context is captured by shims
    env.setdefault("MW05_FORCE_PRESENT_WRAPPER_ONCE", "1")
    env.setdefault("MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS", "240")  # ~4s at 60 Hz
    env.setdefault("MW05_NOTIFY_IMMEDIATE", "0")
    # Visibility into VD control block and swap-edge detection
    env.setdefault("MW05_VD_READ_TRACE", "1")
    env.setdefault("MW05_PM4_SWAP_DETECT", "1")

    env.setdefault("MW05_PM4_SWAP_DETECT_MASK", "0x2")
    # Delay guest ISR dispatch a bit to avoid early-boot crashes (60 ticks ~ 1s at 60 Hz)
    env.setdefault("MW05_GUEST_ISR_DELAY_TICKS", "60")


    if draw_diag:
        env.setdefault("MW05_DRAW_DIAGNOSTIC", "1")
        env["MW05_TITLE_STATE_TRACE"] = "1"

        # In diag mode, avoid FPW to reduce AV risk; rely on natural present path
        env["MW05_FORCE_PRESENT_WRAPPER_ONCE"] = "0"
        env["MW05_FORCE_PRESENT_INNER"] = "0"
        # Extra post-call probes and scans to understand missing prerequisites
        env.setdefault("MW05_PM4_LE", "1")  # Treat syscmd PM4 as little-endian while diagnosing
        env["MW05_FPW_POST_SYSBUF"] = "1"
        env.setdefault("MW05_PM4_SCAN_SYSBUF", "1")
        env.setdefault("MW05_PM4_SCAN_ON_FPW_POST", "1")
        env.setdefault("MW05_PM4_APPLY_STATE", "1")  # Mirror real RT/DS/VP/Scissor when detected
        # After inner present manager returns, attempt a PM4 build within same guest context
        env.setdefault("MW05_INNER_TRY_PM4", "1")

        # Also attempt PM4 build after present wrapper returns
        env.setdefault("MW05_PRES_TRY_PM4", "1")
        env.setdefault("MW05_PRES_TRY_PM4_DEEP", "0")

        # Also, try from the hot 0x82441CF0 loop caller we see in logs
        env.setdefault("MW05_LOOP_TRY_PM4_PRE", "1")
        env.setdefault("MW05_LOOP_TRY_PM4", "1")
        env.setdefault("MW05_LOOP_TRY_PM4_DEEP", "0")

        # Enable deeper PM4 path attempts after inner manager
        env.setdefault("MW05_INNER_TRY_PM4_DEEP", "0")

        # Use the discovered scheduler pointer as ISR context, and swap params so it goes into r3
        env["MW05_VD_ISR_CTX_SCHED"] = "1"
        env.setdefault("MW05_VD_ISR_SWAP_PARAMS", "1")
        # Allow dispatch immediately to test swap path
        env["MW05_GUEST_ISR_DELAY_TICKS"] = "0"
        # Ensure ISR entry always sees scheduler context in r3 regardless of call site
        env.setdefault("MW05_VD_ISR_SWAP_AT_ENTRY", "1")
        env.setdefault("MW05_VD_ISR_FORCE_R3", "1")

        # Aggressive wait/ack nudges so the title's scheduler unblocks
        env.setdefault("MW05_FORCE_ACK_WAIT", "1")
        env.setdefault("MW05_HOST_ISR_ACK_EVENT", "1")
        env.setdefault("MW05_HOST_ISR_FORCE_SIGNAL_LAST_WAIT", "1")
        env.setdefault("MW05_HOST_ISR_SIGNAL_VD_EVENT", "1")
        env.setdefault("MW05_HOST_ISR_NUDGE_ONCE", "1")
        env.setdefault("MW05_HOST_ISR_NUDGE_AFTER", "180")  # ~3s
        # Watch syscmd writes to prove guest PM4 construction
        env.setdefault("MW05_PM4_SYSBUF_WATCH", "1")
        env.setdefault("MW05_PM4_SYSBUF_WATCH_VERBOSE", "1")

        # Keep syscmd header[0] ticking so titles observing progress proceed
        env.setdefault("MW05_PM4_SYSBUF_TICK_HDR", "1")

        # If allocator callback is missing, let shim hand out syscmd payload pointer
        env.setdefault("MW05_FAKE_ALLOC_SYSBUF", "1")


        # Do not force a possibly-wrong ISR context; let central override supply it
        env["MW05_FORCE_GFX_NOTIFY_CB_CTX"] = "0"
        # Start overriding ISR context via VdGetGraphicsInterruptContext immediately using seed
        env.setdefault("MW05_VD_ISR_CTX_SCHED_DELAY_TICKS", "0")
        env.setdefault("MW05_VD_ISR_CTX_SEEN_MIN", "0")
        # Provide a seed for the scheduler/context pointer; can be overridden via --seed-ea
        env.setdefault("MW05_SCHED_R3_EA", "0x82906660")

        # Allow a couple of safe re-fires of the inner present if nothing happens
        env.setdefault("MW05_FPW_RETRIES", "2")
        env.setdefault("MW05_FPW_RETRY_TICKS", "90")
        # Aggressive PM4 diagnosis: scan and bridge syscmd to ring if any data appears
        # Enable detailed PM4 tracing to capture WAIT_REG_MEM addresses/opcodes
        env.setdefault("MW05_PM4_TRACE", "1")
        env.setdefault("MW05_PM4_SNOOP", "1")

        env.setdefault("MW05_PM4_SCAN_ALL_ON_SWAP", "1")
        env.setdefault("MW05_PM4_SCAN_ON_FPW_POST", "1")
        env.setdefault("MW05_PM4_SYSBUF_TO_RING", "1")
        env.setdefault("MW05_FPW_KICK_PM4", "0")

        env.setdefault("MW05_PM4_SCAN_SYSBUF", "1")
        env.setdefault("MW05_PM4_SYSBUF_SEED_HDR", "1")

        # Optional: log TYPE0 register writes and expand register trace budget
        env.setdefault("MW05_PM4_LOG_TYPE0", "1")
        env.setdefault("MW05_PM4_TRACE_REGS", "1")
        env.setdefault("MW05_PM4_TRACE_REG_BUDGET", "4096")

        # Optional: bypass WAIT_REG_MEM packets in syscmd->ring bridge to uncover later commands
        env.setdefault("MW05_PM4_BYPASS_WAITS", "1")


        # Dump syscmd payload after builder returns to catch freshly written PM4 (guarded in shim)
        env.setdefault("MW05_PM4_DUMP_AFTER_BUILDER", "1")

        # Scan syscmd payload after builder returns to run PM4 parser on opcode 0x04 wrapper
        env.setdefault("MW05_PM4_SCAN_AFTER_BUILDER", "1")

        # Deeper instrumentation: dump scheduler ACK blocks and syscmd header on queries
        env.setdefault("MW05_DUMP_SCHED_BLOCK", "1")
        env.setdefault("MW05_PM4_SYSBUF_DUMP_ON_GET", "1")

        # Force a linear scan of the entire System Command Buffer payload on every present
        env.setdefault("MW05_PM4_FORCE_SYSBUF_SCAN", "1")


    if until_draw:
        env.setdefault("MW05_UNTIL_DRAW", "1")
    # Explicit override for PM4 endianness if provided via CLI
    if pm4_le is not None:
        env["MW05_PM4_LE"] = pm4_le
    return env


def stop_process_tree(pid: int, grace: float = 1.5):
    try:
        if sys.platform.startswith('win'):
            # Try gentle terminate first
            try:
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],

                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except Exception:
                pass
        else:
            try:
                os.kill(pid, 15)
                time.sleep(grace)
                os.kill(pid, 9)
            except Exception:
                pass
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description="Run Mw05Recomp with robust timeout and optional early-exit on draw")
    ap.add_argument('--exe', type=Path, default=DEFAULT_EXE, help='Path to Mw05Recomp.exe')
    ap.add_argument('--log', type=Path, default=DEFAULT_LOG, help='Path to mw05_host_trace.log')
    ap.add_argument('--seconds', type=int, default=20, help='Max seconds to run before stopping')
    ap.add_argument('--until-draw', action='store_true', help='Exit early upon detecting first draw in the log')
    ap.add_argument('--draw-diag', action='store_true', help='Enable PM4 draw diagnostics')
    ap.add_argument('--inherit-env', action='store_true', help='Inherit parent environment in addition to debug vars (deprecated: now default)')
    ap.add_argument('--no-inherit-env', action='store_true', help='Do not inherit parent environment; use only MW05_* overrides')
    ap.add_argument('--cwd', type=Path, default=DEFAULT_BUILD_DIR, help='Working directory for the process')
    ap.add_argument('--seed-ea', type=str, default='', help='Optional EA (hex or dec) to pass as MW05_SCHED_R3_EA for FPW once')
    ap.add_argument('--strict', action='store_true', help='Disable aggressive nudges/bypasses to let guest run naturally')
    ap.add_argument('--pm4-le', choices=['0','1'], help='Override MW05_PM4_LE (1=little-endian PM4)')

    args = ap.parse_args()

    exe = args.exe
    if not exe.exists():
        print(f"ERROR: exe not found: {exe}", file=sys.stderr)
        return 2

    cwd = args.cwd
    cwd.mkdir(parents=True, exist_ok=True)

    # Default to inheriting parent environment so hardware GPU/driver/runtime are visible
    from_parent = True
    if getattr(args, 'no_inherit_env', False):
        from_parent = False
    env = build_env(from_parent, args.until_draw, args.draw_diag, strict=getattr(args, 'strict', False), pm4_le=getattr(args, 'pm4_le', None))
    # If user provided a seed EA, pass it via env and slightly reduce FPW delay
    if getattr(args, 'seed_ea', ''):
        env['MW05_SCHED_R3_EA'] = args.seed_ea
        env.setdefault('MW05_FORCE_PRESENT_WRAPPER_DELAY_TICKS', '90')

    # Remove previous summary and truncate previous logs to avoid stale matches
    try:
        if DEFAULT_SUMMARY.exists():
            DEFAULT_SUMMARY.unlink()
    except Exception:
        pass
    try:
        # Truncate host trace log (instead of unlink to avoid races)
        if args.log.exists():
            with open(args.log, 'w', encoding='utf-8') as f:
                f.write("")
    except Exception:
        pass
    try:
        # Truncate debug log file if configured so CMake extract sees only fresh misses
        dbg_log = env.get('MW05_LOG_FILE', '')
        if dbg_log:
            p = Path(dbg_log)
            if p.exists():
                with open(p, 'w', encoding='utf-8') as f:
                    f.write("")
    except Exception:
        pass

    started = time.time()
    print(f"Launching: {exe}")
    proc = subprocess.Popen([str(exe)], cwd=str(cwd), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    exit_reason = "timeout"
    present_entered = 0
    try:
        while True:
            if proc.poll() is not None:
                exit_reason = f"exited({proc.returncode})"
                break
            # Early exit if a draw is detected
            if args.until_draw and tail_has_draw(args.log):
                exit_reason = "until_draw"
                break
            # Stop after timeout
            if (time.time() - started) >= args.seconds:
                exit_reason = "timeout"
                break
            time.sleep(0.4)
    finally:
        if proc.poll() is None:
            stop_process_tree(proc.pid)

    duration = round(time.time() - started, 2)
    # Best-effort summary
    summary = {
        'exe': str(exe),
        'cwd': str(cwd),
        'duration_sec': duration,
        'exit_reason': exit_reason,
        'log_path': str(args.log),
    }
    write_summary(DEFAULT_SUMMARY, summary)

    print(f"Done: {exit_reason} in {duration}s\nSummary: {DEFAULT_SUMMARY}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

