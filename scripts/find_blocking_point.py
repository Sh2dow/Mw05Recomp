#!/usr/bin/env python3
"""
Find what's blocking the game's initialization sequence.
Compare function calls between Xenia and our implementation.
"""

import re
from pathlib import Path
from collections import Counter

def analyze_xenia_log():
    """Extract the call chain that leads to video initialization in Xenia."""
    xenia_log = Path("tools/xenia.log")
    
    print("=" * 80)
    print("XENIA CALL CHAIN TO VIDEO INITIALIZATION")
    print("=" * 80)
    
    # The call stack from line 35516-35549 in Xenia log
    call_chain = [
        "0x828500BC",
        "0x82850918", 
        "0x82850854",
        "0x8261A5B4",
        "0x82441E80",
        "0x823B01B4",
        "0x823AF72C",
        "0x822161A4",
        "0x8244056C",
        "0x824404D0",
        "0x825A16F4",
        "0x825A8738",
        "0x825A8610",
        "sub_82598230"  # Video init function
    ]
    
    print("\nCall chain (top to bottom):")
    for i, addr in enumerate(call_chain):
        print(f"  {i+1:2d}. {addr}")
    
    return call_chain

def check_our_trace(call_chain):
    """Check which functions from the call chain are being called in our trace."""
    trace_log = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not trace_log.exists():
        print(f"\nERROR: Trace log not found: {trace_log}")
        return
    
    print("\n" + "=" * 80)
    print("CHECKING OUR TRACE LOG")
    print("=" * 80)
    
    # Convert addresses to function names
    func_names = []
    for addr in call_chain:
        if addr.startswith("0x"):
            # Convert to sub_XXXXXXXX format
            func_name = f"sub_{addr[2:].upper()}"
        else:
            func_name = addr
        func_names.append(func_name)
    
    print(f"\nSearching for {len(func_names)} functions in trace log...")
    print(f"Trace log size: {trace_log.stat().st_size / 1024 / 1024:.1f} MB")
    
    # Search for each function
    found = {}
    with open(trace_log, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        
        for func_name in func_names:
            count = content.count(func_name)
            found[func_name] = count
    
    print("\nResults:")
    print(f"{'Function':<20} {'Called?':<10} {'Count':<10}")
    print("-" * 40)
    
    for func_name in func_names:
        count = found[func_name]
        status = "✓ YES" if count > 0 else "✗ NO"
        print(f"{func_name:<20} {status:<10} {count:<10}")
    
    # Find the first function that's NOT being called
    print("\n" + "=" * 80)
    print("BLOCKING POINT")
    print("=" * 80)
    
    for i, func_name in enumerate(func_names):
        if found[func_name] == 0:
            print(f"\n✗ BLOCKED AT: {func_name}")
            print(f"  Position in call chain: {i+1}/{len(func_names)}")
            if i > 0:
                prev_func = func_names[i-1]
                print(f"  Previous function (last one called): {prev_func}")
                print(f"  {prev_func} should call {func_name}, but it doesn't!")
            break
    else:
        print("\n✓ All functions in call chain are being called!")
        print("  The blocking point is elsewhere.")

def main():
    call_chain = analyze_xenia_log()
    check_our_trace(call_chain)

if __name__ == "__main__":
    main()

