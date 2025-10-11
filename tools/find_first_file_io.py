#!/usr/bin/env python3
"""Find first file I/O operation in Xenia log."""

with open('tools/xenia.log', 'r', encoding='utf-8', errors='ignore') as f:
    lines = f.readlines()

print(f"Total lines in Xenia log: {len(lines)}")
print()

# Find first file operation
for i, line in enumerate(lines):
    if 'ResolvePath' in line or 'NtCreateFile' in line or 'NtOpenFile' in line or 'NtReadFile' in line:
        print(f"First file operation at line {i}:")
        print()
        
        # Show 20 lines before
        start = max(0, i - 20)
        for j in range(start, i):
            print(f"{j:6d}: {lines[j]}", end='')
        
        # Show the file operation line
        print(f"{i:6d}: >>> {lines[i]}", end='')
        
        # Show 10 lines after
        end = min(len(lines), i + 10)
        for j in range(i + 1, end):
            print(f"{j:6d}: {lines[j]}", end='')
        
        break
else:
    print("No file operations found in Xenia log!")

