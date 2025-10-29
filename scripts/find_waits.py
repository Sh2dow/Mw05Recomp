#!/usr/bin/env python3
"""Find all wait operations in the logs."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("Wait operations:")
    print("=" * 80)
    
    count = 0
    for i, line in enumerate(lines):
        if 'Wait' in line and ('Ke' in line or 'Nt' in line or 'import' in line):
            print(f"Line {i+1}: {line.strip()}")
            count += 1
            if count > 50:
                print("... (truncated)")
                break
    
    if count == 0:
        print("NO wait operations found!")

if __name__ == '__main__':
    main()

