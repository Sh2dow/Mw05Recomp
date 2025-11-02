#!/usr/bin/env python3
"""Monitor memory usage of Mw05Recomp.exe over time."""

import psutil
import time
import sys
import subprocess
import os
from pathlib import Path

def find_process():
    """Find Mw05Recomp.exe process."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'Mw05Recomp.exe':
            return psutil.Process(proc.info['pid'])
    return None

def format_bytes(bytes_val):
    """Format bytes as MB."""
    return f"{bytes_val / (1024 * 1024):.2f} MB"

def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    
    print(f"[MONITOR] Monitoring Mw05Recomp.exe memory for {duration} seconds...")
    print(f"[MONITOR] Columns: Time | WS (MB) | Private WS (MB) | Commit (MB) | Delta WS (MB/s)")
    print("-" * 80)
    
    # Wait for process to start
    proc = None
    for i in range(10):
        proc = find_process()
        if proc:
            break
        time.sleep(0.5)
    
    if not proc:
        print("[ERROR] Mw05Recomp.exe not found!")
        return 1
    
    print(f"[MONITOR] Found process PID={proc.pid}")
    
    start_time = time.time()
    prev_ws = 0
    prev_time = start_time
    
    samples = []
    
    try:
        while time.time() - start_time < duration:
            try:
                mem = proc.memory_info()
                elapsed = time.time() - start_time
                
                # Working set (RSS on Windows)
                ws = mem.rss
                
                # Private working set (not directly available, use rss - shared)
                # On Windows, we can get this from memory_full_info() but it's slow
                # For now, just use rss
                
                # Calculate delta
                delta_time = time.time() - prev_time
                if delta_time > 0:
                    delta_ws = (ws - prev_ws) / delta_time / (1024 * 1024)  # MB/s
                else:
                    delta_ws = 0
                
                # Store sample
                samples.append({
                    'time': elapsed,
                    'ws': ws,
                    'delta': delta_ws
                })
                
                # Print every second
                if len(samples) % 1 == 0:
                    print(f"{elapsed:6.1f}s | {format_bytes(ws):>12} | Delta: {delta_ws:>8.2f} MB/s")
                
                prev_ws = ws
                prev_time = time.time()
                
                time.sleep(1.0)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                print(f"[MONITOR] Process terminated at {time.time() - start_time:.1f}s")
                break
    
    except KeyboardInterrupt:
        print("\n[MONITOR] Interrupted by user")
    
    # Analysis
    print("\n" + "=" * 80)
    print("MEMORY ANALYSIS:")
    print("=" * 80)
    
    if len(samples) < 2:
        print("[ERROR] Not enough samples!")
        return 1
    
    initial_ws = samples[0]['ws']
    final_ws = samples[-1]['ws']
    max_ws = max(s['ws'] for s in samples)
    
    print(f"Initial WS:  {format_bytes(initial_ws)}")
    print(f"Final WS:    {format_bytes(final_ws)}")
    print(f"Max WS:      {format_bytes(max_ws)}")
    print(f"Growth:      {format_bytes(final_ws - initial_ws)} ({(final_ws - initial_ws) / initial_ws * 100:.1f}%)")
    print(f"Avg growth:  {(final_ws - initial_ws) / len(samples) / (1024 * 1024):.2f} MB/s")
    
    # Check for leak pattern
    if final_ws > initial_ws * 1.5:
        print("\n⚠️  WARNING: Memory grew by >50% - possible MEMORY LEAK!")
    elif final_ws > initial_ws * 1.1:
        print("\n⚠️  CAUTION: Memory grew by >10% - investigate growth pattern")
    else:
        print("\n✅ Memory usage stable (growth <10%)")
    
    # Save detailed data
    output_file = Path("traces/memory_monitor.csv")
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w') as f:
        f.write("Time(s),WS(MB),Delta(MB/s)\n")
        for s in samples:
            f.write(f"{s['time']:.1f},{s['ws'] / (1024 * 1024):.2f},{s['delta']:.2f}\n")
    
    print(f"\n[SAVED] Detailed data: {output_file}")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())

