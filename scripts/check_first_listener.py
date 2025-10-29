#!/usr/bin/env python3
"""Check what the first listener (areas=0x05) is waiting for."""

def main():
    with open('traces/auto_test_stderr.txt', 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print("Listener creation:")
    print("=" * 80)
    
    for i, line in enumerate(lines):
        if 'XamNotifyCreateListener areas=' in line:
            print(f"Line {i+1}: {line.strip()}")
            # Show next few lines to see if there are any immediate polls
            for j in range(i+1, min(i+10, len(lines))):
                if 'XNotifyGetNext' in lines[j] or 'XamNotifyEnqueueEvent' in lines[j]:
                    print(f"  Line {j+1}: {lines[j].strip()}")
    
    print("\n" + "=" * 80)
    print("Areas breakdown:")
    print("=" * 80)
    print("First listener: areas=0x05 = 0b00000101")
    print("  Bit 0 (area 0): System notifications (signin, storage, etc.)")
    print("  Bit 2 (area 2): Storage notifications")
    print("\nSecond listener: areas=0x2F = 0b00101111")
    print("  Bit 0 (area 0): System notifications")
    print("  Bit 1 (area 1): ?")
    print("  Bit 2 (area 2): Storage notifications")
    print("  Bit 3 (area 3): ?")
    print("  Bit 5 (area 5): ?")

if __name__ == '__main__':
    main()

