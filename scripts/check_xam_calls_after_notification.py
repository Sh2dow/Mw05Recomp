#!/usr/bin/env python3
"""Check if XAM functions are called after the notification is received."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find when notification is received
    notification_received_line = None
    for i, line in enumerate(lines):
        if 'XNotifyGetNext call=1' in line and 'queue_size=1' in line:
            notification_received_line = i + 1
            print(f"Notification received at line {notification_received_line}:")
            print(f"  {line.strip()}")
            break
    
    if not notification_received_line:
        print("ERROR: Could not find notification received event")
        return
    
    # Check for XAM function calls after notification
    print("\n" + "=" * 80)
    print(f"Checking for XAM function calls after line {notification_received_line}:")
    print("=" * 80)
    
    xam_functions = [
        'XamUserGetSigninState',
        'XamUserGetXUID',
        'XamUserGetName',
        'XamContentGetDeviceState',
        'XamContentCreateEx',
        'XamGetSystemVersion',
        'XamUserCheckPrivilege',
    ]
    
    found_any = False
    for i in range(notification_received_line, min(notification_received_line + 1000, len(lines))):
        line = lines[i]
        for func in xam_functions:
            if func in line and '[HOST.' in line:
                print(f"Line {i+1}: {line.strip()}")
                found_any = True
                break
    
    if not found_any:
        print("NO XAM functions called after notification received!")
        print("\nThis means the game received the notification but didn't call any XAM functions.")
        print("The game's state machine is stuck waiting for something else.")

if __name__ == '__main__':
    main()

