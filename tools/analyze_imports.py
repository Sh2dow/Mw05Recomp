#!/usr/bin/env python3
"""Analyze which imports are being called."""

import re
from collections import Counter

def analyze_imports(filename):
    """Count import function calls."""
    
    imports = Counter()
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Match import calls
            match = re.search(r'import=__imp__([A-Za-z0-9_]+)', line)
            if match:
                func_name = match.group(1)
                imports[func_name] += 1
    
    return imports

if __name__ == '__main__':
    log_file = 'out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log'
    
    print("Analyzing import calls...")
    imports = analyze_imports(log_file)
    
    print(f"\nTop 30 most called imports:")
    for func, count in imports.most_common(30):
        print(f"  {count:8d}  {func}")
    
    print(f"\nTotal unique imports: {len(imports)}")
    print(f"Total import calls: {sum(imports.values())}")
    
    # Check for file I/O
    file_io_funcs = ['NtCreateFile', 'NtOpenFile', 'NtReadFile', 'NtWriteFile', 'NtClose']
    print(f"\nFile I/O functions:")
    for func in file_io_funcs:
        count = imports.get(func, 0)
        print(f"  {func}: {count}")

