#!/usr/bin/env python3
"""Find XamInputGetState calls."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("XamInputGetState calls:")
    print("=" * 80)
    
    count = 0
    for i, line in enumerate(lines):
        if 'XamInputGetState' in line and 'Import' not in line:
            print(f"Line {i+1}: {line.strip()}")
            count += 1
            if count > 50:
                print("... (truncated)")
                break
    
    if count == 0:
        print("NO XamInputGetState calls found!")
        print("\nThis means the game is NOT polling for controller input.")
        print("The game might be stuck waiting for something else entirely.")

if __name__ == '__main__':
    main()

