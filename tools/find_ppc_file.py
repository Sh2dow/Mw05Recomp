#!/usr/bin/env python3
"""Find which PPC file contains a given host offset."""

import sys
import os
import re

def find_ppc_file(offset_hex):
    """Find which PPC file contains the given host offset."""
    offset = int(offset_hex, 16)
    
    # Get all ppc_recomp.*.cpp files
    ppc_dir = "Mw05RecompLib/ppc"
    files = []
    for filename in os.listdir(ppc_dir):
        if filename.startswith("ppc_recomp.") and filename.endswith(".cpp"):
            # Extract file number
            match = re.match(r"ppc_recomp\.(\d+)\.cpp", filename)
            if match:
                file_num = int(match.group(1))
                filepath = os.path.join(ppc_dir, filename)
                file_size = os.path.getsize(filepath)
                files.append((file_num, filename, file_size))
    
    # Sort by file number
    files.sort()
    
    # Calculate cumulative offsets
    cumulative = 0
    for file_num, filename, file_size in files:
        if cumulative <= offset < cumulative + file_size:
            offset_in_file = offset - cumulative
            print(f"Host offset: +0x{offset:X}")
            print(f"File: {filename}")
            print(f"Offset in file: +0x{offset_in_file:X} ({offset_in_file} bytes)")
            print(f"File size: {file_size} bytes")
            print(f"Cumulative offset: +0x{cumulative:X}")
            return filename, offset_in_file
        cumulative += file_size
    
    print(f"Host offset +0x{offset:X} is beyond all PPC files (total size: {cumulative} bytes)")
    return None, None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python find_ppc_file.py <host_offset_hex>")
        print("Example: python find_ppc_file.py 0xF02668")
        sys.exit(1)
    
    find_ppc_file(sys.argv[1])

