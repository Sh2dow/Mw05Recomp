#!/usr/bin/env python3
"""
Analyze why MW05 isn't rendering despite running without crashes.
"""

import re
from collections import Counter, defaultdict

def analyze_trace_log(log_path):
    """Analyze the trace log to understand the rendering state."""
    
    print("=" * 80)
    print("MW05 NO-RENDER DIAGNOSTIC")
    print("=" * 80)
    
    # Read the log file
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log: {e}")
        return
    
    print(f"\nTotal log lines: {len(lines):,}")
    
    # Extract key metrics
    pm4_types = defaultdict(int)
    pm4_opcodes = Counter()
    draw_count = 0
    packet_count = 0
    present_count = 0
    vblank_count = 0
    threads = set()
    null_calls = []
    
    # Scan for specific patterns
    for line in lines:
        # PM4 packet types
        if 'PM4.Types' in line:
            match = re.search(r't0=(\d+) t1=(\d+) t2=(\d+) t3=(\d+)', line)
            if match:
                pm4_types['TYPE0'] = int(match.group(1))
                pm4_types['TYPE1'] = int(match.group(2))
                pm4_types['TYPE2'] = int(match.group(3))
                pm4_types['TYPE3'] = int(match.group(4))
        
        # PM4 opcodes
        if 'PM4.OPC[' in line:
            match = re.search(r'PM4\.OPC\[([0-9A-F]+)\]=(\d+)', line)
            if match:
                opcode = match.group(1)
                count = int(match.group(2))
                pm4_opcodes[opcode] = count
        
        # Draw count
        if 'DrawCount=' in line:
            match = re.search(r'DrawCount=(\d+)', line)
            if match:
                draw_count = max(draw_count, int(match.group(1)))
        
        # Present calls
        if 'VideoPresent.enter' in line:
            present_count += 1
        
        # Vblank ticks
        if 'VBLANK-TICK' in line:
            vblank_count += 1
        
        # Thread IDs
        if 'tid=' in line:
            match = re.search(r'tid=([0-9a-f]+)', line)
            if match:
                threads.add(match.group(1))
        
        # NULL-CALL tracking
        if 'NULL-CALL' in line:
            null_calls.append(line.strip())
    
    # Report findings
    print("\n" + "=" * 80)
    print("PM4 PACKET ANALYSIS")
    print("=" * 80)
    
    if pm4_types:
        print(f"\nPacket Type Distribution:")
        for ptype, count in sorted(pm4_types.items()):
            print(f"  {ptype}: {count:,}")
        
        total_packets = sum(pm4_types.values())
        if total_packets > 0:
            print(f"\nTotal PM4 packets: {total_packets:,}")
            print(f"  TYPE0 (register writes): {pm4_types['TYPE0']/total_packets*100:.1f}%")
            print(f"  TYPE3 (commands):        {pm4_types['TYPE3']/total_packets*100:.1f}%")
    
    if pm4_opcodes:
        print(f"\nPM4 Opcodes Observed ({len(pm4_opcodes)} unique):")
        for opcode, count in pm4_opcodes.most_common(20):
            opcode_name = get_opcode_name(opcode)
            print(f"  0x{opcode}: {count:,} - {opcode_name}")
    else:
        print("\n⚠️  NO PM4 OPCODES FOUND (no TYPE3 packets)")
    
    print("\n" + "=" * 80)
    print("RENDERING STATUS")
    print("=" * 80)
    
    print(f"\nDraw Commands: {draw_count}")
    print(f"Present Calls: {present_count}")
    print(f"Vblank Ticks:  {vblank_count}")
    print(f"Active Threads: {len(threads)}")
    
    if draw_count == 0:
        print("\n❌ PROBLEM: No draw commands detected!")
        print("\nPossible causes:")
        print("  1. Game is still loading/initializing")
        print("  2. Game is waiting for input or a specific event")
        print("  3. Draw commands are in indirect buffers not being followed")
        print("  4. Game uses a different rendering path (system command buffer)")
        print("  5. GPU initialization is incomplete")
    
    if pm4_types.get('TYPE3', 0) == 0:
        print("\n❌ CRITICAL: No TYPE3 (command) packets at all!")
        print("   Only TYPE0 (register writes) are being submitted.")
        print("   This suggests the game is stuck in GPU setup phase.")
    
    if null_calls:
        print(f"\n⚠️  NULL-CALL count: {len(null_calls)}")
        print("Recent NULL-CALLs:")
        for call in null_calls[-5:]:
            print(f"  {call}")
    
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    
    if pm4_types.get('TYPE3', 0) == 0:
        print("\n1. Check if game is waiting for a specific GPU register/state")
        print("2. Compare with Xenia trace to see when TYPE3 packets appear")
        print("3. Check if VdSwap is being called by the game (not just forced)")
        print("4. Verify GPU initialization sequence matches Xbox 360 expectations")
        print("5. Check if game is polling for GPU idle/ready state")
    
    print("\n" + "=" * 80)


def get_opcode_name(opcode_hex):
    """Map PM4 opcode to name."""
    opcodes = {
        '10': 'NOP',
        '22': 'DRAW_INDX',
        '36': 'DRAW_INDX_2',
        '3F': 'INDIRECT_BUFFER',
        '3C': 'WAIT_REG_MEM',
        '46': 'EVENT_WRITE',
        '48': 'ME_INIT',
        '2D': 'SET_CONSTANT',
        '32': 'SET_SHADER_CONSTANTS',
    }
    return opcodes.get(opcode_hex, 'UNKNOWN')


if __name__ == '__main__':
    log_path = '../../out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    analyze_trace_log(log_path)

