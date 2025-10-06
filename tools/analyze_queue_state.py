#!/usr/bin/env python3
"""Analyze MW05 queue state and command flow."""

import sys
import re
from collections import defaultdict

def analyze_log(log_path):
    """Analyze the MW05 trace log for queue state and command patterns."""
    
    # Track queue state over time
    queue_states = []
    writeback_updates = []
    pm4_commands = []
    micro_ib_peeks = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Track queue state
            if 'HOST.Sched.825979A8' in line:
                match = re.search(r'base=([0-9A-F]+) qhead=([0-9A-F]+) qtail=([0-9A-F]+)', line)
                if match:
                    queue_states.append({
                        'base': match.group(1),
                        'qhead': match.group(2),
                        'qtail': match.group(3)
                    })
            
            # Track writeback updates
            if 'rb_writeback' in line or 'gpu_id_writeback' in line:
                writeback_updates.append(line.strip())
            
            # Track PM4 commands
            if 'PM4.OPC[04]' in line:
                match = re.search(r'PM4\.OPC\[04\]=(\d+)', line)
                if match:
                    pm4_commands.append(int(match.group(1)))
            
            # Track micro-IB peeks
            if 'PM4.MW05.MicroIB.peek' in line and 'tail' not in line:
                match = re.search(r'ea=([0-9A-F]+) d0=([0-9A-F]+) d1=([0-9A-F]+) d2=([0-9A-F]+) d3=([0-9A-F]+)', line)
                if match:
                    micro_ib_peeks.append({
                        'ea': match.group(1),
                        'd0': match.group(2),
                        'd1': match.group(3),
                        'd2': match.group(2),
                        'd3': match.group(4)
                    })
    
    print("=" * 80)
    print("MW05 QUEUE STATE ANALYSIS")
    print("=" * 80)
    
    # Analyze queue progression
    print("\n### Queue State Progression:")
    unique_states = []
    for state in queue_states:
        state_key = f"{state['base']}:{state['qhead']}:{state['qtail']}"
        if not unique_states or unique_states[-1] != state_key:
            unique_states.append(state_key)
    
    print(f"Total queue state samples: {len(queue_states)}")
    print(f"Unique queue states: {len(unique_states)}")
    print("\nUnique states:")
    for state_key in unique_states[:20]:  # Show first 20
        parts = state_key.split(':')
        print(f"  base={parts[0]} qhead={parts[1]} qtail={parts[2]}")
    
    # Check if queue is stuck
    if len(unique_states) <= 5:
        print("\n⚠️  WARNING: Queue appears STUCK - very few state changes!")
    
    # Analyze writeback updates
    print(f"\n### Writeback Updates:")
    print(f"Total writeback updates: {len(writeback_updates)}")
    if writeback_updates:
        print("First 5 updates:")
        for update in writeback_updates[:5]:
            print(f"  {update}")
        print("Last 5 updates:")
        for update in writeback_updates[-5:]:
            print(f"  {update}")
    
    # Analyze PM4 commands
    print(f"\n### PM4 Opcode 04 Commands:")
    print(f"Total opcode 04 commands detected: {len(pm4_commands)}")
    if pm4_commands:
        print(f"Command count range: {min(pm4_commands)} to {max(pm4_commands)}")
        print(f"Unique command counts: {len(set(pm4_commands))}")
    
    # Analyze micro-IB peeks
    print(f"\n### Micro-IB Peeks:")
    print(f"Total micro-IB peeks: {len(micro_ib_peeks)}")
    if micro_ib_peeks:
        print("First peek:")
        peek = micro_ib_peeks[0]
        print(f"  ea={peek['ea']} d0={peek['d0']} d1={peek['d1']} d3={peek['d3']}")
        
        # Check for MW05 magic header
        has_magic = any(p['d0'] == '3530574D' or p['d1'] == '3530574D' for p in micro_ib_peeks)
        if has_magic:
            print("✓ MW05 magic header (0x3530574D) FOUND!")
        else:
            print("✗ MW05 magic header (0x3530574D) NOT FOUND")
        
        # Check for sentinel values
        has_sentinel = any(p['d1'] == 'FFFAFEFD' for p in micro_ib_peeks)
        if has_sentinel:
            print("✓ Sentinel value (0xFFFAFEFD) found")
    
    print("\n" + "=" * 80)
    
    # Diagnosis
    print("\n### DIAGNOSIS:")
    if len(unique_states) <= 5 and len(writeback_updates) > 0:
        print("✗ Queue is STUCK despite writeback updates")
        print("  → MW05 is receiving writeback signals but not writing new commands")
        print("  → Likely waiting for:")
        print("    - GPU fence completion events")
        print("    - Shader compilation/execution")
        print("    - Texture uploads")
        print("    - File I/O completion")
        print("    - User input")
    elif len(writeback_updates) == 0:
        print("✗ No writeback updates detected")
        print("  → Writeback mechanism may not be working")
    else:
        print("? Queue state unclear - needs more investigation")
    
    print("=" * 80)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python analyze_queue_state.py <log_file>")
        sys.exit(1)
    
    analyze_log(sys.argv[1])

