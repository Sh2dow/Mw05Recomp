#!/usr/bin/env python3
import re
import sys

def find_function_size(html_path, target_addr):
    """Find the size of a function by finding the next function start."""
    with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
        html = f.read()
    
    # Find all function starts
    funcs = set()
    for m in re.finditer(r'sub_([0-9A-Fa-f]{8})', html):
        funcs.add(int(m.group(1), 16))
    
    funcs = sorted(funcs)
    
    # Find target function
    if target_addr not in funcs:
        print(f"Function 0x{target_addr:08X} not found in HTML!")
        return None
    
    idx = funcs.index(target_addr)
    if idx + 1 < len(funcs):
        next_func = funcs[idx + 1]
        size = next_func - target_addr
        print(f"0x{target_addr:08X}: next func at 0x{next_func:08X}, size = 0x{size:X} ({size} bytes)")
        return size
    else:
        print(f"0x{target_addr:08X}: last function in file!")
        return None

if __name__ == '__main__':
    html_path = 'NfsMWEurope.xex.html'
    
    # Find sizes for the two missing functions
    find_function_size(html_path, 0x82855308)
    find_function_size(html_path, 0x821B71E0)

