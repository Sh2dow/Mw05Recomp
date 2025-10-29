#!/usr/bin/env python3
"""Find input-related function calls."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("Input-related function calls:")
    print("=" * 80)
    
    keywords = ['Input', 'GetState', 'XInput', 'Controller', 'Gamepad', 'Button', 'Key']
    
    count = 0
    for i, line in enumerate(lines):
        if any(keyword in line for keyword in keywords):
            print(f"Line {i+1}: {line.strip()}")
            count += 1
            if count > 100:
                print("... (truncated)")
                break
    
    if count == 0:
        print("NO input-related calls found!")

if __name__ == '__main__':
    main()

