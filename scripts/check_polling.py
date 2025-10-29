#!/usr/bin/env python3
"""Check which listener the game is polling."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find listener handles
    listeners = {}
    for i, line in enumerate(lines):
        if 'XamNotifyCreateListener areas=' in line and 'handle=' in line:
            parts = line.split('handle=')
            if len(parts) > 1:
                handle = parts[1].split()[0]
                areas = line.split('areas=')[1].split()[0]
                listeners[handle] = areas
                print(f"Listener {handle} created with areas={areas} at line {i+1}")
    
    print("\n" + "=" * 80)
    print("XNotifyGetNext calls:")
    print("=" * 80)
    
    # Find XNotifyGetNext calls
    for i, line in enumerate(lines[:5000]):  # Only check first 5000 lines
        if 'XNotifyGetNext' in line and 'hNotification=' in line:
            parts = line.split('hNotification=')
            if len(parts) > 1:
                handle = parts[1].split()[0]
                if handle in listeners:
                    print(f"Line {i+1}: Polling listener {handle} (areas={listeners[handle]})")
                    print(f"  {line.strip()}")
                    if i > 2500:
                        print("... (truncated)")
                        break

if __name__ == '__main__':
    main()

