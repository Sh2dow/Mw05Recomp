#!/usr/bin/env python3
"""Check if the shim binary contains the new code"""

import os
import sys

def main():
    obj_path = r'out\build\x64-Clang-Debug\Mw05Recomp\CMakeFiles\Mw05Recomp.dir\gpu\mw05_trace_shims.cpp.obj'
    
    if not os.path.exists(obj_path):
        print(f"ERROR: Object file not found: {obj_path}")
        return 1
    
    # Check file timestamp
    mtime = os.path.getmtime(obj_path)
    import datetime
    dt = datetime.datetime.fromtimestamp(mtime)
    print(f"Object file timestamp: {dt}")
    
    # Check source file timestamp
    src_path = r'Mw05Recomp\gpu\mw05_trace_shims.cpp'
    if os.path.exists(src_path):
        src_mtime = os.path.getmtime(src_path)
        src_dt = datetime.datetime.fromtimestamp(src_mtime)
        print(f"Source file timestamp: {src_dt}")
        
        if src_mtime > mtime:
            print("WARNING: Source file is NEWER than object file!")
        else:
            print("Object file is up to date")
    
    # Search for the new string in the object file
    print("\nSearching for new strings in object file...")
    with open(obj_path, 'rb') as f:
        data = f.read()
    
    # Search for the new log messages
    if b'attempting to seed' in data:
        print("✓ Found 'attempting to seed' in object file")
    else:
        print("✗ NOT FOUND: 'attempting to seed' in object file")
    
    if b'seeded_from_env' in data:
        print("✓ Found 'seeded_from_env' in object file")
    else:
        print("✗ NOT FOUND: 'seeded_from_env' in object file")
    
    if b'still_invalid' in data:
        print("✓ Found 'still_invalid' in object file")
    else:
        print("✗ NOT FOUND: 'still_invalid' in object file")
    
    # Check the executable
    print("\nSearching for new strings in executable...")
    exe_path = r'out\build\x64-Clang-Debug\Mw05Recomp\Mw05Recomp.exe'
    if os.path.exists(exe_path):
        exe_mtime = os.path.getmtime(exe_path)
        exe_dt = datetime.datetime.fromtimestamp(exe_mtime)
        print(f"Executable timestamp: {exe_dt}")
        
        with open(exe_path, 'rb') as f:
            exe_data = f.read()
        
        if b'attempting to seed' in exe_data:
            print("✓ Found 'attempting to seed' in executable")
        else:
            print("✗ NOT FOUND: 'attempting to seed' in executable")
        
        if b'seeded_from_env' in exe_data:
            print("✓ Found 'seeded_from_env' in executable")
        else:
            print("✗ NOT FOUND: 'seeded_from_env' in executable")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

