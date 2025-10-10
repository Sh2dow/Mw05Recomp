#!/usr/bin/env python3
"""
Find what memory address the main thread is polling in its spin loop.
"""

import re
import sys
from collections import Counter

def find_spin_loop_address(log_path):
    """Find the memory address being polled."""
    
    main_tid = 'a9c4'
    
    # Track Load/Store addresses
    load_addresses = Counter()
    store_addresses = Counter()
    
    print(f"Analyzing main thread {main_tid} spin loop...")
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if f'tid={main_tid}' in line:
                # Extract Load addresses
                load_match = re.search(r'LoadBE32_Watched.*ea=([0-9A-Fa-f]+)', line)
                if load_match:
                    addr = load_match.group(1)
                    load_addresses[addr] += 1
                
                # Extract Store addresses
                store_match = re.search(r'StoreBE32_Watched.*ea=([0-9A-Fa-f]+)', line)
                if store_match:
                    addr = store_match.group(1)
                    store_addresses[addr] += 1
    
    print("\n" + "="*80)
    print("TOP 20 MOST FREQUENTLY LOADED ADDRESSES (spin loop candidates)")
    print("="*80)
    for addr, count in load_addresses.most_common(20):
        print(f"0x{addr}: {count:8d} loads")
    
    print("\n" + "="*80)
    print("TOP 20 MOST FREQUENTLY STORED ADDRESSES")
    print("="*80)
    for addr, count in store_addresses.most_common(20):
        print(f"0x{addr}: {count:8d} stores")
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total Load operations: {sum(load_addresses.values())}")
    print(f"Total Store operations: {sum(store_addresses.values())}")
    print(f"Unique Load addresses: {len(load_addresses)}")
    print(f"Unique Store addresses: {len(store_addresses)}")
    
    if load_addresses:
        top_addr, top_count = load_addresses.most_common(1)[0]
        total_loads = sum(load_addresses.values())
        pct = (top_count / total_loads * 100) if total_loads > 0 else 0
        print(f"\nMost polled address: 0x{top_addr} ({top_count} loads, {pct:.1f}% of all loads)")
        print(f"This is likely the spin loop condition variable!")

if __name__ == '__main__':
    log_path = sys.argv[1] if len(sys.argv) > 1 else 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    find_spin_loop_address(log_path)

