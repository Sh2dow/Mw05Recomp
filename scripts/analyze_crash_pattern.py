#!/usr/bin/env python3
"""
Analyze the crash pattern to understand what's happening.
The crash is at offset +0x7270F in Mw05Recomp.exe, called from +0x9A1296 (PPC code).
"""

import subprocess
import re
import sys

def run_game_and_capture():
    """Run the game and capture the output."""
    cmd = [
        'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', 'D:/Repos/Games/Mw05Recomp/run_game.ps1'
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            cwd='D:/Repos/Games/Mw05Recomp'
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        print("Game timed out after 30 seconds")
        return None
    except Exception as e:
        print(f"Error running game: {e}")
        return None

def analyze_crash(output):
    """Analyze the crash output."""
    if not output:
        return
    
    # Find NULL-CALL messages
    null_calls = re.findall(r'\[NULL-CALL\] lr=([0-9A-F]+) target=([0-9A-F]+) r3=([0-9A-F]+)', output)
    print(f"Found {len(null_calls)} NULL-CALL messages:")
    for lr, target, r3 in null_calls:
        print(f"  lr=0x{lr}, target=0x{target}, r3=0x{r3}")
    
    # Find crash information
    crash_match = re.search(r'\[crash\] unhandled exception code=0x([0-9A-F]+) addr=0x([0-9A-F]+) tid=([0-9A-F]+)', output)
    if crash_match:
        code, addr, tid = crash_match.groups()
        print(f"\nCrash detected:")
        print(f"  Exception code: 0x{code}")
        print(f"  Address: 0x{addr}")
        print(f"  Thread ID: 0x{tid}")
        
        # Calculate offset from base
        base = 0x7ff659840000  # This is the base address from the crash log
        offset = int(addr, 16) - base
        print(f"  Offset from base: +0x{offset:X}")
    
    # Find recent Store64BE_W calls before crash
    store_calls = re.findall(r'\[TRACE\].*Store64BE_W\.called ea=([0-9A-F]+) val=([0-9A-F]+) tid=([0-9A-F]+)', output)
    if store_calls:
        print(f"\nFound {len(store_calls)} Store64BE_W calls")
        print("Last 10 Store64BE_W calls before crash:")
        for ea, val, tid in store_calls[-10:]:
            print(f"  ea=0x{ea}, val=0x{val}, tid=0x{tid}")

if __name__ == '__main__':
    print("Running game to capture crash...")
    output = run_game_and_capture()
    if output:
        analyze_crash(output)
    else:
        print("Failed to capture game output")
        sys.exit(1)

