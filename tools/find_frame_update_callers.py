#!/usr/bin/env python3
"""Find all places that call sub_8262DE60 (frame update) in the main loop."""

import re

# Read the generated code
with open('Mw05RecompLib/ppc/ppc_recomp.54.cpp', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

# Find all calls to sub_8262DE60
print("=== Calls to sub_8262DE60 in ppc_recomp.54.cpp ===\n")

for i, line in enumerate(lines, 1):
    if 'sub_8262DE60' in line and 'bl ' in line:
        # Print context around the call
        start = max(0, i - 5)
        end = min(len(lines), i + 10)
        print(f"Line {i}:")
        for j in range(start, end):
            marker = ">>> " if j == i - 1 else "    "
            print(f"{marker}{j+1:5d}: {lines[j]}", end='')
        print("\n" + "="*80 + "\n")

print("\n=== Summary ===")
print(f"Total lines in file: {len(lines)}")

