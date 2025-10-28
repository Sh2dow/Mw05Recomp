#!/usr/bin/env python3
"""Analyze VBLANK timing from mw05_host_trace.log"""

import re
from collections import Counter

# Read log file
with open('out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log', encoding='utf-8') as f:
    lines = f.readlines()

# Extract timing data
timing_lines = [l for l in lines if 'VblankPump.timing' in l]

# Parse loop_ms values
loop_ms_values = []
for line in timing_lines:
    m = re.search(r'loop_ms=(\d+)', line)
    if m:
        loop_ms_values.append(int(m.group(1)))

# Calculate statistics
if loop_ms_values:
    print(f"Total ticks: {len(loop_ms_values)}")
    print(f"Min loop_ms: {min(loop_ms_values)}")
    print(f"Max loop_ms: {max(loop_ms_values)}")
    print(f"Avg loop_ms: {sum(loop_ms_values) / len(loop_ms_values):.1f}")
    print(f"Median loop_ms: {sorted(loop_ms_values)[len(loop_ms_values)//2]}")
    
    # Distribution
    print("\nloop_ms distribution:")
    counter = Counter(loop_ms_values)
    for ms in sorted(counter.keys()):
        count = counter[ms]
        pct = 100.0 * count / len(loop_ms_values)
        print(f"  {ms:3d}ms: {count:4d} ticks ({pct:5.1f}%)")
    
    # Check for outliers (>50ms)
    outliers = [ms for ms in loop_ms_values if ms > 50]
    if outliers:
        print(f"\nOutliers (>50ms): {len(outliers)} ticks ({100.0*len(outliers)/len(loop_ms_values):.1f}%)")
        print(f"  Max outlier: {max(outliers)}ms")

