#!/usr/bin/env python3
"""Check the timing of notification creation vs listener creation."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    listener_line = None
    notification_line = None
    
    for i, line in enumerate(lines):
        if 'XamNotifyCreateListener' in line and listener_line is None:
            listener_line = i + 1  # 1-based
            print(f"First listener created at line {listener_line}:")
            print(f"  {line.strip()}")
        
        if 'XamNotifyEnqueueEvent id=00000011' in line and notification_line is None:
            notification_line = i + 1  # 1-based
            print(f"\nFirst notification 0x11 sent at line {notification_line}:")
            print(f"  {line.strip()}")
            break
    
    if listener_line and notification_line:
        if notification_line < listener_line:
            print(f"\n✓ Notification sent BEFORE listener created (good)")
        else:
            print(f"\n✗ Notification sent AFTER listener created (bad - notification missed)")
            print(f"  Difference: {notification_line - listener_line} lines")

if __name__ == '__main__':
    main()

