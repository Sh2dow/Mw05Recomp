#!/usr/bin/env python3
"""Check how many listeners are created and when."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("Listeners created:")
    print("=" * 80)
    
    for i, line in enumerate(lines):
        if 'XamNotifyCreateListener areas=' in line:
            print(f"Line {i+1}: {line.strip()}")
    
    print("\n" + "=" * 80)
    print("\nNotifications sent:")
    print("=" * 80)
    
    for i, line in enumerate(lines):
        if 'XamNotifyEnqueueEvent id=' in line:
            print(f"Line {i+1}: {line.strip()}")
            if i > 2000:  # Only show first few
                print("... (truncated)")
                break

if __name__ == '__main__':
    main()

