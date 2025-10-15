#!/usr/bin/env python3
"""
Analyze stderr output from MW05 to identify blocking patterns.
"""

import sys
import re
from collections import defaultdict, Counter
from pathlib import Path

def analyze_stderr(stderr_file: Path):
    """Analyze stderr output to find blocking patterns."""
    
    print("=" * 80)
    print("MW05 Stderr Analysis")
    print("=" * 80)
    
    if not stderr_file.exists():
        print(f"[!] Stderr file not found: {stderr_file}")
        return
    
    with open(stderr_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"\n[*] Total lines: {len(lines)}")
    
    # Count different message types
    stub_calls = []
    not_impl_calls = []
    vdswap_calls = []
    pm4_scans = []
    vblank_ticks = []
    thread_creations = []
    import_patches = []
    
    for line in lines:
        if 'STUB:' in line:
            stub_calls.append(line.strip())
        elif 'NOT IMPLEMENTED' in line or '!!!' in line:
            not_impl_calls.append(line.strip())
        elif 'VdSwap' in line:
            vdswap_calls.append(line.strip())
        elif 'PM4_ScanLinear' in line:
            pm4_scans.append(line.strip())
        elif 'VBLANK-TICK' in line:
            vblank_ticks.append(line.strip())
        elif 'Thread #' in line and 'created' in line:
            thread_creations.append(line.strip())
        elif 'Import' in line and 'PATCHED' in line:
            import_patches.append(line.strip())
    
    print(f"\n[*] Message Type Counts:")
    print(f"    STUB calls: {len(stub_calls)}")
    print(f"    NOT IMPLEMENTED calls: {len(not_impl_calls)}")
    print(f"    VdSwap calls: {len(vdswap_calls)}")
    print(f"    PM4 scans: {len(pm4_scans)}")
    print(f"    VBlank ticks: {len(vblank_ticks)}")
    print(f"    Thread creations: {len(thread_creations)}")
    print(f"    Import patches: {len(import_patches)}")
    
    # Analyze thread creations
    if thread_creations:
        print(f"\n[*] Thread Creations:")
        for thread in thread_creations[:10]:  # Show first 10
            print(f"    {thread}")
    
    # Analyze PM4 scans
    if pm4_scans:
        print(f"\n[*] PM4 Scan Results:")
        draws_found = False
        for scan in pm4_scans[:10]:  # Show first 10
            print(f"    {scan}")
            if 'draws=' in scan:
                match = re.search(r'draws=(\d+)', scan)
                if match and int(match.group(1)) > 0:
                    draws_found = True
        
        if not draws_found:
            print(f"\n[!] NO DRAWS FOUND in PM4 scans - game hasn't issued draw commands yet")
    
    # Analyze VBlank ticks
    if vblank_ticks:
        print(f"\n[*] VBlank Ticks: {len(vblank_ticks)} ticks")
        if len(vblank_ticks) > 0:
            print(f"    First tick: {vblank_ticks[0]}")
            print(f"    Last tick: {vblank_ticks[-1]}")
    
    # Analyze stub calls
    if stub_calls:
        print(f"\n[*] Top 10 STUB Calls:")
        stub_counter = Counter(stub_calls)
        for stub, count in stub_counter.most_common(10):
            print(f"    {count:5d}x {stub}")
    
    # Analyze NOT IMPLEMENTED calls
    if not_impl_calls:
        print(f"\n[*] Top 10 NOT IMPLEMENTED Calls:")
        not_impl_counter = Counter(not_impl_calls)
        for call, count in not_impl_counter.most_common(10):
            print(f"    {count:5d}x {call}")
    
    # Check for specific blocking indicators
    print(f"\n[*] Blocking Indicators:")
    
    # Check if audio registration happened
    audio_reg_found = any('XAudioRegisterRenderDriverClient' in line or 'sub_8285BC80' in line for line in lines)
    if audio_reg_found:
        print(f"    [+] Audio registration detected")
    else:
        print(f"    [!] NO audio registration - game hasn't called XAudioRegisterRenderDriverClient")
    
    # Check if file I/O happened
    file_io_found = any('NtCreateFile' in line or 'NtOpenFile' in line or 'NtReadFile' in line for line in lines)
    if file_io_found:
        print(f"    [+] File I/O detected")
    else:
        print(f"    [!] NO file I/O - game hasn't started loading resources")
    
    # Check if KeSetEvent was called
    set_event_found = any('KeSetEvent' in line for line in lines)
    if set_event_found:
        print(f"    [+] KeSetEvent detected")
    else:
        print(f"    [!] NO KeSetEvent - events are never being signaled")
    
    # Check for graphics callback registration
    gfx_callback_found = any('NATURAL-REG' in line or 'VdSetGraphicsInterruptCallback' in line for line in lines)
    if gfx_callback_found:
        print(f"    [+] Graphics callback registered")
    else:
        print(f"    [!] NO graphics callback registration")
    
    print("\n" + "=" * 80)
    print("Analysis Complete!")
    print("=" * 80)

def main():
    stderr_file = Path("out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt")
    
    if len(sys.argv) > 1:
        stderr_file = Path(sys.argv[1])
    
    analyze_stderr(stderr_file)
    return 0

if __name__ == "__main__":
    sys.exit(main())

