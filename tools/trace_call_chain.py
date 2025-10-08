#!/usr/bin/env python3
"""Trace the call chain backwards to find the root trigger"""

import os
import sys
import re

def find_callers(ida_lines, target_func):
    """Find all functions that call the target function"""
    callers = []
    pattern = f'bl.*sub_{target_func}'
    
    for i, line in enumerate(ida_lines):
        if re.search(pattern, line, re.IGNORECASE):
            # Extract the address of the calling instruction
            match = re.search(r'\.text:([0-9A-Fa-f]{8})', line)
            if match:
                call_addr = match.group(1).upper()
                callers.append((call_addr, i+1, line.rstrip()))
    
    return callers

def find_function_start(ida_lines, addr):
    """Find the function that contains the given address"""
    addr_int = int(addr, 16)
    
    # Search backwards for function start
    for i in range(len(ida_lines)):
        match = re.search(r'\.text:([0-9A-Fa-f]{8})\s+sub_([0-9A-Fa-f]{8}):', ida_lines[i])
        if match:
            func_addr = match.group(2).upper()
            func_addr_int = int(func_addr, 16)
            
            # Check if this function might contain our address
            if func_addr_int <= addr_int:
                # Look ahead to see if the function extends to our address
                # Assume functions are at most 10000 lines
                for j in range(i, min(len(ida_lines), i + 10000)):
                    if re.search(r'# End of function', ida_lines[j]):
                        # Check if our address is before the end
                        end_match = re.search(r'\.text:([0-9A-Fa-f]{8})', ida_lines[j])
                        if end_match:
                            end_addr_int = int(end_match.group(1), 16)
                            if func_addr_int <= addr_int <= end_addr_int:
                                return func_addr
                        break
    
    return None

def main():
    ida_path = 'NfsMWEurope.xex.html'
    
    if not os.path.exists(ida_path):
        print(f"ERROR: IDA export not found: {ida_path}")
        return 1
    
    print("Loading IDA export...")
    with open(ida_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Loaded {len(lines)} lines")
    
    # Trace the call chain backwards
    print("\n" + "="*80)
    print("TRACING CALL CHAIN BACKWARDS")
    print("="*80)
    
    # Start with sub_82849DE8 (video thread creation trigger)
    chain = ['82849DE8']
    
    print("\nStarting from sub_82849DE8 (video thread creation trigger)")
    print("Tracing backwards to find the root caller...\n")
    
    for depth in range(10):  # Max depth of 10
        current = chain[-1]
        print(f"\n--- Level {depth}: Finding callers of sub_{current} ---")
        
        callers = find_callers(lines, current)
        
        if not callers:
            print(f"No callers found for sub_{current}")
            break
        
        print(f"Found {len(callers)} call sites:")
        for call_addr, line_num, line_text in callers[:5]:  # Show first 5
            print(f"  {call_addr}: {line_text}")
        
        # Find the function that contains the first caller
        first_caller_addr = callers[0][0]
        func_addr = find_function_start(lines, first_caller_addr)
        
        if func_addr:
            print(f"\nFirst caller is in sub_{func_addr}")
            if func_addr in chain:
                print(f"CYCLE DETECTED: sub_{func_addr} already in chain")
                break
            chain.append(func_addr)
        else:
            print(f"Could not find function containing {first_caller_addr}")
            break
    
    print("\n" + "="*80)
    print("CALL CHAIN (from root to target)")
    print("="*80)
    chain.reverse()
    for i, func in enumerate(chain):
        print(f"{i}: sub_{func}")
    
    # Check which functions in the chain are being called
    print("\n" + "="*80)
    print("CHECKING WHICH FUNCTIONS ARE CALLED IN LOG")
    print("="*80)
    
    log_path = r'out\build\x64-Clang-Debug\Mw05Recomp\mw05_host_trace.log'
    if os.path.exists(log_path):
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()
        
        for func in chain:
            if func in log_content:
                print(f"✓ sub_{func} IS called")
            else:
                print(f"✗ sub_{func} is NOT called")
    else:
        print(f"Log file not found: {log_path}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

