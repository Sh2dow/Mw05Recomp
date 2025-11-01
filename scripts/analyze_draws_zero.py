#!/usr/bin/env python3
"""
Analyze why the game is stuck at draws=0.
This script examines the logs to find what's preventing the game from issuing draw commands.
"""

import re
from pathlib import Path
from collections import Counter

def analyze_logs():
    """Analyze the game logs to find the root cause of draws=0."""
    
    stderr_file = Path("traces/auto_test_stderr.txt")
    stdout_file = Path("traces/auto_test_stdout.txt")
    
    if not stderr_file.exists() or not stdout_file.exists():
        print("ERROR: Log files not found. Run the game first.")
        return
    
    print("=" * 80)
    print("ANALYZING DRAWS=0 ISSUE")
    print("=" * 80)
    
    # Read logs
    with open(stderr_file, "r", encoding="utf-8", errors="ignore") as f:
        stderr_lines = f.readlines()
    
    with open(stdout_file, "r", encoding="utf-8", errors="ignore") as f:
        stdout_lines = f.readlines()
    
    # 1. Check if XamInputGetState is being called
    input_calls = [line for line in stdout_lines if "XamInputGetState" in line or "auto_start" in line]
    print(f"\n1. INPUT POLLING:")
    print(f"   XamInputGetState calls: {len(input_calls)}")
    if len(input_calls) == 0:
        print("   ❌ Game is NOT polling for input - stuck before title screen!")
    else:
        print("   ✅ Game is polling for input")
        if input_calls:
            print(f"   First call: {input_calls[0].strip()}")
    
    # 2. Check Init functions
    init_pattern = re.compile(r'Init(\d+)')
    init_calls = {}
    for line in stderr_lines:
        match = init_pattern.search(line)
        if match:
            init_num = match.group(1)
            init_calls[init_num] = init_calls.get(init_num, 0) + 1
    
    print(f"\n2. INITIALIZATION FUNCTIONS:")
    for i in range(1, 9):
        count = init_calls.get(str(i), 0)
        status = "✅" if count > 0 else "❌"
        print(f"   {status} Init{i}: {count} calls")
    
    # 3. Check PM4 command types
    pm4_types = Counter()
    for line in stdout_lines:
        if "PM4" in line and "opc=" in line:
            match = re.search(r'opc=([0-9A-F]+)', line)
            if match:
                pm4_types[match.group(1)] += 1
    
    print(f"\n3. PM4 COMMAND TYPES:")
    if pm4_types:
        for opc, count in pm4_types.most_common(10):
            print(f"   Opcode 0x{opc}: {count} commands")
    else:
        print("   No PM4 opcode data found")
    
    # 4. Check file loading
    file_reads_ok = len([line for line in stdout_lines if "io.read" in line and "ok=1" in line])
    file_reads_fail = len([line for line in stdout_lines if "io.read" in line and "ok=0" in line])
    ack_no_path = len([line for line in stdout_lines if "ack.no_path" in line])
    
    print(f"\n4. FILE LOADING:")
    print(f"   Successful reads: {file_reads_ok}")
    print(f"   Failed reads: {file_reads_fail}")
    print(f"   Acknowledged without path: {ack_no_path}")
    
    # 5. Check present callback
    present_calls = len([line for line in stderr_lines if "PRESENT-CB" in line or "sub_82598A20" in line])
    print(f"\n5. PRESENT CALLBACK:")
    print(f"   sub_82598A20 calls: {present_calls}")
    
    # 6. Check for specific error patterns
    print(f"\n6. ERROR PATTERNS:")
    errors = [
        ("Heap corruption", [line for line in stderr_lines if "corruption" in line.lower()]),
        ("Assertion failures", [line for line in stderr_lines if "assert" in line.lower() or "ASSERT" in line]),
        ("NULL pointer", [line for line in stderr_lines if "NULL" in line or "nullptr" in line]),
        ("Invalid address", [line for line in stderr_lines if "invalid" in line.lower() and "address" in line.lower()]),
    ]
    
    for error_name, error_lines in errors:
        if error_lines:
            print(f"   ❌ {error_name}: {len(error_lines)} occurrences")
            if error_lines:
                print(f"      Example: {error_lines[0].strip()[:100]}")
        else:
            print(f"   ✅ {error_name}: None")
    
    # 7. Summary and diagnosis
    print(f"\n" + "=" * 80)
    print("DIAGNOSIS:")
    print("=" * 80)
    
    if len(input_calls) == 0:
        print("\n🔍 ROOT CAUSE: Game is stuck in PRE-TITLE-SCREEN initialization")
        print("   The game is NOT polling for input, which means it hasn't reached")
        print("   the title screen yet. It's stuck in an earlier initialization phase.")
        print("\n   Possible causes:")
        print("   1. Waiting for a specific file to load")
        print("   2. Waiting for a callback to be invoked")
        print("   3. Waiting for a flag/state to be set")
        print("   4. Stuck in an infinite loop")
        
        # Check if it's a file loading issue
        if file_reads_fail > file_reads_ok * 2:
            print("\n   ⚠️  LIKELY CAUSE: File loading failures")
            print(f"      Failed reads ({file_reads_fail}) >> Successful reads ({file_reads_ok})")
            print("      The game may be waiting for specific files that aren't loading.")
        elif ack_no_path > 100:
            print("\n   ⚠️  LIKELY CAUSE: Loader block acknowledgment without actual I/O")
            print(f"      {ack_no_path} blocks acknowledged without extracting file paths")
            print("      The game thinks files loaded but they didn't - causing state mismatch.")
        else:
            print("\n   ⚠️  LIKELY CAUSE: Missing initialization step or callback")
            print("      Files are loading, but game isn't progressing to next phase.")
            print("      Need to investigate what condition the game is waiting for.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    analyze_logs()

