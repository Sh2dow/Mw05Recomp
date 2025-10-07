#!/usr/bin/env python3
import sys

def get_function_size(html_file, func_name):
    with open(html_file) as f:
        lines = f.readlines()
    
    # Find function start
    start_idx = None
    for i, line in enumerate(lines):
        if func_name in line and 'PROC' in line:
            start_idx = i
            break
    
    if start_idx is None:
        print(f"Function {func_name} not found")
        return
    
    # Find function end
    end_idx = None
    for i in range(start_idx, len(lines)):
        if 'ENDP' in lines[i]:
            end_idx = i
            break
    
    if end_idx is None:
        print(f"ENDP not found for {func_name}")
        return
    
    # Extract addresses
    start_line = lines[start_idx]
    end_line = lines[end_idx]
    
    # Parse address from ".text:82596978"
    start_addr = int(start_line.split()[0].split(':')[1], 16)
    end_addr = int(end_line.split()[0].split(':')[1], 16)
    
    size = end_addr - start_addr
    
    print(f"Function: {func_name}")
    print(f"Start: 0x{start_addr:08X}")
    print(f"End: 0x{end_addr:08X}")
    print(f"Size: 0x{size:X} ({size} bytes)")

if __name__ == '__main__':
    get_function_size('NfsMWEurope.xex.html', 'sub_825968B0')

