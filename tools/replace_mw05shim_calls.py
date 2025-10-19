#!/usr/bin/env python3
"""Replace all MW05Shim_sub_* calls with sub_* calls."""

import re
import sys
from pathlib import Path

def replace_shim_calls(content: str) -> str:
    """Replace MW05Shim_sub_XXXXXXXX calls with sub_XXXXXXXX calls."""
    # Pattern to match MW05Shim_sub_XXXXXXXX(
    pattern = r'MW05Shim_(sub_[0-9A-F]{8})\('
    replacement = r'\1('
    return re.sub(pattern, replacement, content)

def main():
    if len(sys.argv) != 2:
        print("Usage: python replace_mw05shim_calls.py <file_path>")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Read the file
    content = file_path.read_text(encoding='utf-8')
    
    # Replace calls
    converted = replace_shim_calls(content)
    
    # Write back
    file_path.write_text(converted, encoding='utf-8')
    
    print(f"Successfully replaced MW05Shim_* calls in {file_path}")

if __name__ == '__main__':
    main()

