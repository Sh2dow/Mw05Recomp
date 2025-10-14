#!/usr/bin/env python3
"""Check if the notification polling loop is exiting properly."""

import re

def main():
    # Read our trace log
    with open('out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log', 'r') as f:
        lines = f.readlines()
    
    # Find all XNotifyGetNext calls
    notify_calls = []
    for i, line in enumerate(lines):
        if 'XNotifyGetNext' in line:
            notify_calls.append((i, line.strip()))
    
    print(f"Total XNotifyGetNext calls: {len(notify_calls)}")
    
    if notify_calls:
        print(f"\nFirst call (line {notify_calls[0][0]}):")
        print(f"  {notify_calls[0][1]}")
        
        print(f"\nLast call (line {notify_calls[-1][0]}):")
        print(f"  {notify_calls[-1][1]}")
        
        # Check if there are any lines after the last XNotifyGetNext call
        last_line = notify_calls[-1][0]
        total_lines = len(lines)
        lines_after = total_lines - last_line - 1
        
        print(f"\nTotal trace lines: {total_lines}")
        print(f"Lines after last XNotifyGetNext: {lines_after}")
        
        if lines_after > 100:
            print("\n✅ Game is progressing AFTER the notification loop!")
            print("\nSample of activity after last XNotifyGetNext:")
            for i in range(last_line + 1, min(last_line + 21, total_lines)):
                print(f"  {lines[i].strip()}")
        else:
            print("\n⚠️ Game is NOT progressing after the notification loop")
            print("The trace ends shortly after the last XNotifyGetNext call")
    
    # Check for the specific thread (6f0c) that was polling
    print("\n" + "="*80)
    print("Checking thread 6f0c activity...")
    
    thread_lines = [line for line in lines if 'tid=6f0c' in line]
    print(f"Total lines from thread 6f0c: {len(thread_lines)}")
    
    if thread_lines:
        print("\nFirst 5 lines from thread 6f0c:")
        for line in thread_lines[:5]:
            print(f"  {line.strip()}")
        
        print("\nLast 5 lines from thread 6f0c:")
        for line in thread_lines[-5:]:
            print(f"  {line.strip()}")
    
    # Check for graphics initialization
    print("\n" + "="*80)
    print("Checking for graphics initialization...")
    
    vd_init = [line for line in lines if 'VdInitializeRingBuffer' in line or 'VdEnableRingBufferRPtrWriteBack' in line]
    if vd_init:
        print(f"✅ Graphics initialization found! ({len(vd_init)} calls)")
        for line in vd_init:
            print(f"  {line.strip()}")
    else:
        print("❌ No graphics initialization found")
    
    # Check for render thread creation (0x825AA970)
    print("\n" + "="*80)
    print("Checking for render thread creation...")
    
    render_thread = [line for line in lines if '825AA970' in line]
    if render_thread:
        print(f"✅ Render thread created! ({len(render_thread)} references)")
        for line in render_thread[:5]:
            print(f"  {line.strip()}")
    else:
        print("❌ Render thread NOT created (entry point 0x825AA970 not found)")

if __name__ == '__main__':
    main()

