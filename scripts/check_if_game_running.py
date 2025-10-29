#!/usr/bin/env python3
"""Check if the game is actually running after the notification."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find notification received line
    notif_line = None
    for i, line in enumerate(lines):
        if 'XNotifyGetNext call=1' in line and 'queue_size=1' in line:
            notif_line = i
            break
    
    if not notif_line:
        print("ERROR: Could not find notification")
        return
    
    print(f"Notification received at line {notif_line + 1}")
    print("=" * 80)
    
    # Count main loop iterations after notification
    iterations_before = 0
    iterations_after = 0
    
    for i in range(notif_line):
        if 'MW05_MAIN_LOOP] Iteration' in lines[i]:
            iterations_before += 1
    
    for i in range(notif_line, len(lines)):
        if 'MW05_MAIN_LOOP] Iteration' in lines[i]:
            iterations_after += 1
    
    print(f"Main loop iterations BEFORE notification: {iterations_before}")
    print(f"Main loop iterations AFTER notification: {iterations_after}")
    
    if iterations_after > 0:
        print("\n✓ Game IS running after notification!")
        print("  The game is NOT frozen - it's just stuck in a pre-initialization state.")
    else:
        print("\n✗ Game STOPPED after notification!")
        print("  The game might have crashed or frozen.")

if __name__ == '__main__':
    main()

