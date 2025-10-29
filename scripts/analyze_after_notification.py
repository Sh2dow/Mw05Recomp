#!/usr/bin/env python3
"""Analyze what happens after the notification is received."""

import re

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find when notification is received
    notification_line = None
    for i, line in enumerate(lines):
        if 'XNotifyGetNext call=1' in line and 'queue_size=1' in line:
            notification_line = i
            break
    
    if not notification_line:
        print("ERROR: Could not find notification received event")
        return
    
    print(f"Notification received at line {notification_line + 1}")
    print("=" * 80)
    print("\nNext 50 lines after notification:")
    print("=" * 80)
    
    for i in range(notification_line, min(notification_line + 50, len(lines))):
        line = lines[i].rstrip()
        # Highlight important lines
        if any(keyword in line for keyword in ['sub_', 'INIT-TRACE', 'heap', 'XAM', 'FILE', 'MAIN-LOOP']):
            print(f"{i+1:6d}: {line}")

if __name__ == '__main__':
    main()

