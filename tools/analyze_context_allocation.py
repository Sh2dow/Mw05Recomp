#!/usr/bin/env python3
"""
Analyze Xenia log to find where context 0x40007180 is allocated.
"""

import re
import sys

def analyze_log(log_path):
    """Find allocation of context structure at 0x40007180."""
    
    target_addr = 0x40007180
    target_range_start = 0x40000000
    target_range_end = 0x40010000
    
    print(f"Searching for allocation of context at 0x{target_addr:08X}...")
    print(f"Looking for allocations in range 0x{target_range_start:08X} - 0x{target_range_end:08X}\n")
    
    allocations = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            # Look for MmAllocatePhysicalMemory calls
            if 'MmAllocatePhysicalMemory' in line:
                # Extract address from the line
                # Format: "i> F8000XXX [MW05] MmAllocatePhysicalMemory size=0xXXXX ea=0xXXXXXXXX"
                match = re.search(r'ea=0x([0-9A-Fa-f]+)', line)
                if match:
                    addr = int(match.group(1), 16)
                    if target_range_start <= addr < target_range_end:
                        # Extract size
                        size_match = re.search(r'size=0x([0-9A-Fa-f]+)', line)
                        size = int(size_match.group(1), 16) if size_match else 0
                        
                        allocations.append({
                            'line': line_num,
                            'addr': addr,
                            'size': size,
                            'end': addr + size,
                            'text': line.strip()
                        })
                        
                        # Check if target address falls within this allocation
                        if addr <= target_addr < addr + size:
                            print(f"✓ FOUND! Line {line_num}:")
                            print(f"  Address: 0x{addr:08X}")
                            print(f"  Size: 0x{size:X} ({size} bytes)")
                            print(f"  End: 0x{addr+size:08X}")
                            print(f"  Target 0x{target_addr:08X} is at offset +0x{target_addr-addr:X}")
                            print(f"  {line.strip()}\n")
            
            # Stop after first 40000 lines (before VdSetGraphicsInterruptCallback)
            if line_num > 40000:
                break
    
    print(f"\nAll allocations in range 0x{target_range_start:08X} - 0x{target_range_end:08X}:")
    print(f"{'Line':<8} {'Address':<12} {'Size':<10} {'End':<12} {'Contains Target?'}")
    print("-" * 70)
    
    for alloc in allocations:
        contains = "YES" if alloc['addr'] <= target_addr < alloc['end'] else ""
        print(f"{alloc['line']:<8} 0x{alloc['addr']:08X}   0x{alloc['size']:<6X}   0x{alloc['end']:08X}   {contains}")
    
    if not allocations:
        print("No allocations found in the target range!")
        print("\nSearching for any reference to 0x40007180...")
        
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if '40007180' in line or '0x40007180' in line.lower():
                    print(f"Line {line_num}: {line.strip()}")
                    if line_num > 5:  # Show first few occurrences
                        break

if __name__ == '__main__':
    log_path = 'tools/xenia.log'
    analyze_log(log_path)

