#!/usr/bin/env python3
"""Find the function that contains a given link register address."""

import re
import sys

def find_function_containing_address(html_file, target_addr):
    """Find the function that contains the given address."""
    with open(html_file, 'r', encoding='utf-8') as f:
        html = f.read()
    
    # Find all function starts
    func_pattern = r'<a name="([0-9A-F]+)"></a>'
    func_matches = re.findall(func_pattern, html)
    
    # Convert target address to int
    target = int(target_addr, 16)
    
    # Find the function that contains this address
    # The function start is the largest address that is <= target
    func_start = None
    for addr_str in func_matches:
        addr = int(addr_str, 16)
        if addr <= target:
            if func_start is None or addr > func_start:
                func_start = addr
    
    if func_start is None:
        return None, None
    
    # Convert back to hex string
    func_start_str = f'{func_start:08X}'
    
    # Extract the function code
    func_code_pattern = f'<a name="{func_start_str}"></a>.*?<pre>(.*?)</pre>'
    func_code_match = re.search(func_code_pattern, html, re.DOTALL)
    
    if func_code_match:
        return func_start_str, func_code_match.group(1)
    else:
        return func_start_str, None

if __name__ == '__main__':
    html_file = 'NfsMWEurope.xex.html'

    # Link register addresses from the crash
    lr_addresses = ['82596900', '825969E0']

    # First, let's check what addresses are in the HTML file
    with open(html_file, 'r', encoding='utf-8') as f:
        html = f.read()

    func_pattern = r'<a name="([0-9A-F]+)"></a>'
    func_matches = re.findall(func_pattern, html)

    print(f'Total functions in HTML: {len(func_matches)}')
    if func_matches:
        func_addrs = [int(addr, 16) for addr in func_matches]
        print(f'First function: 0x{min(func_addrs):08X}')
        print(f'Last function: 0x{max(func_addrs):08X}')

    for lr_addr in lr_addresses:
        lr_int = int(lr_addr, 16)
        print(f'\nLR address: 0x{lr_int:08X}')

        func_start, func_code = find_function_containing_address(html_file, lr_addr)

        if func_start:
            print(f'=== LR={lr_addr} is in function sub_{func_start} ===')
            if func_code:
                # Print first 50 lines of the function
                lines = func_code.split('\n')
                for i, line in enumerate(lines[:50]):
                    print(line)
                if len(lines) > 50:
                    print(f'... ({len(lines) - 50} more lines)')
        else:
            print(f'=== LR={lr_addr} NOT FOUND ===')

