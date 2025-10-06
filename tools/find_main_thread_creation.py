#!/usr/bin/env python3
"""
Find where the main thread F8000008 is created in Xenia log.
"""

def main():
    log_file = 'tools/xenia.log'
    
    print("Reading Xenia log...")
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Total lines: {len(lines)}")
    
    # Find where thread F8000008 is first mentioned
    for i, line in enumerate(lines):
        if 'F8000008' in line:
            print(f"\nFirst mention of F8000008 at line {i}:")
            # Show 20 lines before and 10 lines after
            start = max(0, i - 20)
            end = min(len(lines), i + 11)
            for j in range(start, end):
                marker = ">>>" if j == i else "   "
                print(f"{marker} {j:6d}: {lines[j].rstrip()}")
            break

if __name__ == '__main__':
    main()

