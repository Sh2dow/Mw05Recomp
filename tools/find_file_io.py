#!/usr/bin/env python3
"""Find file I/O operations in Xenia log before first draw."""

import re

def find_file_io_before_draw(filename, max_line=36075):
    """Find file I/O operations before the first draw."""
    
    file_io_lines = []
    
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= max_line:
                break
            
            if re.search(r'NtReadFile|NtOpenFile|NtCreateFile', line):
                file_io_lines.append((i, line.strip()))
    
    return file_io_lines

if __name__ == '__main__':
    print("Searching for file I/O operations in Xenia log before first draw (line 36075)...")
    file_io = find_file_io_before_draw('tools/xenia.log')
    
    print(f"\nFound {len(file_io)} file I/O operations")
    
    if file_io:
        print("\nFirst 20 file I/O operations:")
        for i, (line_num, line) in enumerate(file_io[:20]):
            print(f"{line_num:6d}: {line}")
        
        print(f"\nLast 20 file I/O operations before first draw:")
        for i, (line_num, line) in enumerate(file_io[-20:]):
            print(f"{line_num:6d}: {line}")
    else:
        print("\nNo file I/O operations found!")

