#!/usr/bin/env python3
"""Find what's calling the XNotifyGetNext function repeatedly."""

from pathlib import Path

def main():
    log_path = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if not log_path.exists():
        print(f"ERROR: {log_path} not found!")
        return
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    # Find the first XNotifyGetNext call
    first_notify_idx = -1
    for i, line in enumerate(lines):
        if '__imp__XNotifyGetNext' in line and 'tid=60bc' in line:
            first_notify_idx = i
            break
    
    if first_notify_idx < 0:
        print("ERROR: Could not find first XNotifyGetNext call!")
        return
    
    print(f"\n=== CONTEXT BEFORE FIRST XNotifyGetNext CALL ===")
    print(f"First call at line {first_notify_idx + 1}\n")
    
    # Show 50 lines before
    start = max(0, first_notify_idx - 50)
    end = first_notify_idx + 5
    
    for i in range(start, end):
        marker = ">>> " if i == first_notify_idx else "    "
        print(f"{marker}{i+1:6d}: {lines[i].rstrip()}")
    
    # Now find the second XNotifyGetNext call (after FOUND)
    second_notify_idx = -1
    for i in range(first_notify_idx + 1, len(lines)):
        if '__imp__XNotifyGetNext' in lines[i] and 'tid=60bc' in lines[i]:
            # Skip the "HOST.XNotifyGetNext count=" lines
            if 'HOST.XNotifyGetNext count=' not in lines[i]:
                second_notify_idx = i
                break
    
    if second_notify_idx < 0:
        print("\nERROR: Could not find second XNotifyGetNext call!")
        return
    
    print(f"\n\n=== CONTEXT BEFORE SECOND XNotifyGetNext CALL ===")
    print(f"Second call at line {second_notify_idx + 1}\n")
    
    # Show 30 lines before
    start = max(0, second_notify_idx - 30)
    end = second_notify_idx + 5
    
    for i in range(start, end):
        marker = ">>> " if i == second_notify_idx else "    "
        print(f"{marker}{i+1:6d}: {lines[i].rstrip()}")

if __name__ == "__main__":
    main()

