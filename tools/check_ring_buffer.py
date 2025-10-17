#!/usr/bin/env python3
"""
Check if the PM4 ring buffer contains any non-zero data.
This helps diagnose why we're not seeing draw commands.
"""

import sys
import re
from pathlib import Path

def analyze_trace_log(log_path):
    """Analyze the trace log to find ring buffer status."""
    
    ring_base = None
    ring_size = None
    ring_scratch_pattern = None
    ring_scratch_armed = False
    
    print(f"Analyzing trace log: {log_path}")
    print("=" * 80)
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Find ring buffer initialization
            if 'PM4.SetRingBuffer' in line:
                match = re.search(r'base=([0-9A-F]+)\s+size_log2=(\d+)\s+size=([0-9A-F]+)', line)
                if match:
                    ring_base = int(match.group(1), 16)
                    ring_size = int(match.group(3), 16)
                    print(f"✓ Ring buffer initialized:")
                    print(f"  Base: 0x{ring_base:08X}")
                    print(f"  Size: 0x{ring_size:08X} ({ring_size} bytes)")
            
            # Find ring scratch pattern
            if 'PM4.RingScratch.armed' in line:
                match = re.search(r'pattern=([0-9A-F]+)', line)
                if match:
                    ring_scratch_pattern = int(match.group(1), 16)
                    ring_scratch_armed = True
                    print(f"✓ Ring scratch armed with pattern: 0x{ring_scratch_pattern:08X}")
            
            # Find ring buffer scans
            if 'PM4.ScanAll' in line and 'begin' in line:
                match = re.search(r'base=([0-9A-F]+)\s+size=(\d+)', line)
                if match:
                    scan_base = int(match.group(1), 16)
                    scan_size = int(match.group(2))
                    print(f"✓ Ring buffer scan: base=0x{scan_base:08X} size={scan_size}")
            
            # Find ring buffer scan results
            if 'PM4.ScanAll' in line and 'end' in line:
                match = re.search(r'scanned=(\d+)\s+draws=(\d+)', line)
                if match:
                    scanned = int(match.group(1))
                    draws = int(match.group(2))
                    print(f"  Scanned {scanned} packets, found {draws} draws")
            
            # Find ring buffer memory stats
            if 'PM4.RingMemStats' in line:
                match = re.search(r'nonzero=(\d+)/(\d+)', line)
                if match:
                    nonzero = int(match.group(1))
                    total = int(match.group(2))
                    percent = (nonzero * 100.0) / total if total > 0 else 0
                    print(f"✓ Ring buffer memory stats:")
                    print(f"  Non-zero DWORDs: {nonzero}/{total} ({percent:.2f}%)")
                    if nonzero == 0:
                        print(f"  ⚠️  Ring buffer is EMPTY - game is not writing any data!")
                    elif nonzero == total:
                        print(f"  ⚠️  Ring buffer is FULL - might still contain scratch pattern!")
                    else:
                        print(f"  ✓ Ring buffer has data - game is writing commands!")
    
    print("=" * 80)
    
    # Summary
    if ring_base is None:
        print("❌ ERROR: Ring buffer was never initialized!")
        print("   The game needs to call VdInitializeRingBuffer")
        return False
    
    if not ring_scratch_armed:
        print("⚠️  WARNING: Ring scratch pattern was not armed")
        print("   Cannot detect if game is writing to ring buffer")
        return False
    
    return True

def main():
    # Find the most recent trace log
    trace_log = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not trace_log.exists():
        print(f"ERROR: Trace log not found: {trace_log}")
        print("Run the game first to generate a trace log")
        return 1
    
    success = analyze_trace_log(trace_log)
    
    if not success:
        print("\n❌ DIAGNOSIS: Ring buffer initialization failed")
        print("   Check kernel/imports.cpp VdInitializeRingBuffer implementation")
        return 1
    
    print("\n✓ DIAGNOSIS COMPLETE")
    print("  Check the output above to see if the ring buffer contains data")
    print("  If 'Non-zero DWORDs' is 0, the game is not writing PM4 commands")
    print("  If 'Non-zero DWORDs' is > 0, the game IS writing commands (check if they're being scanned)")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

