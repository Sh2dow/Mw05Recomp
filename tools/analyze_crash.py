#!/usr/bin/env python3
"""
Analyze crash output from MW05 recomp to identify the crashing function.
"""

import sys
import re

def analyze_crash(log_text):
    """Analyze crash log to find the crashing location."""
    
    # Find crash address
    crash_match = re.search(r'\[crash\] unhandled exception code=0x([0-9A-F]+) addr=0x([0-9A-F]+)', log_text)
    if not crash_match:
        print("No crash found in log")
        return
    
    exception_code = crash_match.group(1)
    crash_addr = crash_match.group(2)
    
    print(f"Exception Code: 0x{exception_code}")
    print(f"Crash Address: 0x{crash_addr}")
    print()
    
    # Find all stack frames
    frames = re.findall(r'\[crash\]\s+frame\[(\d+)\] = 0x([0-9A-Fa-f]+) module=(.+?) base=0x([0-9A-Fa-f]+) \+0x([0-9A-Fa-f]+)', log_text)
    
    if frames:
        print("Stack Trace:")
        for frame_num, addr, module, base, offset in frames:
            module_name = module.split('\\')[-1]
            print(f"  [{frame_num}] 0x{addr} = {module_name} + 0x{offset}")
        print()
    
    # Check if it's an access violation
    if exception_code == 'C0000005':
        print("This is an ACCESS VIOLATION (reading/writing invalid memory)")
        print()
        
        # Look for the first frame in Mw05Recomp.exe
        for frame_num, addr, module, base, offset in frames:
            if 'Mw05Recomp.exe' in module:
                print(f"First frame in Mw05Recomp.exe:")
                print(f"  Frame [{frame_num}]: offset +0x{offset}")
                
                # Try to identify if it's in recompiled PPC code
                offset_int = int(offset, 16)
                if offset_int > 0x100000:  # Likely in PPC recompiled code
                    print(f"  This appears to be in recompiled PPC code (large offset)")
                else:
                    print(f"  This appears to be in host code (small offset)")
                break
    
    # Look for context about what was happening before the crash
    print("\nContext before crash:")
    lines = log_text.split('\n')
    crash_line_idx = next((i for i, line in enumerate(lines) if '[crash]' in line), None)
    if crash_line_idx:
        # Print last 20 lines before crash
        start = max(0, crash_line_idx - 20)
        for line in lines[start:crash_line_idx]:
            if line.strip() and not line.startswith('[?'):
                print(f"  {line}")

if __name__ == '__main__':
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8', errors='ignore') as f:
            log_text = f.read()
    else:
        log_text = sys.stdin.read()
    
    analyze_crash(log_text)

