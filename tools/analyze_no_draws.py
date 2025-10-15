#!/usr/bin/env python3
"""
Analyze why draw commands are not being issued.
Examines PM4 command buffer contents and graphics state.
"""

import re
import sys
from collections import Counter, defaultdict

def analyze_pm4_types(log_path):
    """Analyze PM4 packet types to see what commands are being issued."""
    print("\n=== PM4 Packet Type Analysis ===")
    
    type_pattern = re.compile(r'PM4\.Types t0=(\d+) t1=(\d+) t2=(\d+) t3=(\d+)')
    
    type_counts = Counter()
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = type_pattern.search(line)
            if match:
                t0, t1, t2, t3 = map(int, match.groups())
                type_counts['t0'] += t0
                type_counts['t1'] += t1
                type_counts['t2'] += t2
                type_counts['t3'] += t3
    
    if type_counts:
        print(f"Total PM4 packets by type:")
        for ptype, count in sorted(type_counts.items()):
            print(f"  {ptype}: {count:,}")
    else:
        print("No PM4 type information found")
    
    return type_counts

def analyze_graphics_state(log_path):
    """Analyze graphics state initialization."""
    print("\n=== Graphics State Analysis ===")
    
    # Look for key graphics initialization calls
    patterns = {
        'SetRenderTarget': r'SetRenderTarget',
        'SetDepthStencil': r'SetDepthStencil',
        'SetViewport': r'SetViewport',
        'SetScissor': r'SetScissor',
        'LoadShader': r'shader|Shader',
        'LoadTexture': r'texture|Texture',
        'SetVertexBuffer': r'VertexBuffer|VB',
        'SetIndexBuffer': r'IndexBuffer|IB',
    }
    
    found = defaultdict(int)
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for name, pattern in patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    found[name] += 1
    
    if found:
        print("Graphics state calls found:")
        for name, count in sorted(found.items()):
            print(f"  {name}: {count}")
    else:
        print("No graphics state calls found")
    
    return found

def analyze_file_io(log_path):
    """Analyze file I/O to see if resources are being loaded."""
    print("\n=== File I/O Analysis ===")
    
    file_patterns = {
        'NtCreateFile': r'NtCreateFile',
        'NtOpenFile': r'NtOpenFile',
        'NtReadFile': r'NtReadFile',
        'NtWriteFile': r'NtWriteFile',
        'XamContentCreateEx': r'XamContentCreateEx',
    }
    
    found = defaultdict(int)
    files_opened = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for name, pattern in file_patterns.items():
                if re.search(pattern, line):
                    found[name] += 1
            
            # Extract file paths
            if 'NtCreateFile' in line or 'NtOpenFile' in line:
                # Try to extract filename
                match = re.search(r'path[=:][\s]*["\']?([^"\']+)["\']?', line)
                if match:
                    files_opened.append(match.group(1))
    
    if found:
        print("File I/O calls:")
        for name, count in sorted(found.items()):
            print(f"  {name}: {count}")
    else:
        print("No file I/O calls found")
    
    if files_opened:
        print(f"\nFiles accessed ({len(files_opened)} total):")
        for f in files_opened[:10]:
            print(f"  {f}")
        if len(files_opened) > 10:
            print(f"  ... and {len(files_opened) - 10} more")
    
    return found, files_opened

def analyze_thread_activity(log_path):
    """Analyze which threads are active."""
    print("\n=== Thread Activity Analysis ===")
    
    thread_activity = Counter()
    render_thread_ids = ['6270', '54dc', '2914']  # From earlier logs
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Extract thread ID
            match = re.search(r'tid=([0-9a-f]+)', line)
            if match:
                tid = match.group(1)
                thread_activity[tid] += 1
    
    if thread_activity:
        print(f"Thread activity (top 10):")
        for tid, count in thread_activity.most_common(10):
            is_render = " (RENDER THREAD)" if tid in render_thread_ids else ""
            print(f"  tid={tid}: {count:,} log entries{is_render}")
    
    # Check if render threads are active
    render_active = sum(thread_activity[tid] for tid in render_thread_ids if tid in thread_activity)
    if render_active > 0:
        print(f"\nRender threads ARE active ({render_active:,} total log entries)")
    else:
        print("\nRender threads NOT active!")
    
    return thread_activity

def analyze_vdswap_pattern(log_path):
    """Analyze VdSwap call pattern."""
    print("\n=== VdSwap Pattern Analysis ===")
    
    vdswap_calls = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'VdSwap' in line and 'present_requested' in line:
                # Extract r3, r4, r5 parameters
                match = re.search(r'r3=0x([0-9A-Fa-f]+)\s+r4=0x([0-9A-Fa-f]+)\s+r5=0x([0-9A-Fa-f]+)', line)
                if match:
                    r3, r4, r5 = match.groups()
                    vdswap_calls.append((r3, r4, r5))
    
    if vdswap_calls:
        print(f"VdSwap called {len(vdswap_calls)} times")
        print(f"First call: r3=0x{vdswap_calls[0][0]} r4=0x{vdswap_calls[0][1]} r5=0x{vdswap_calls[0][2]}")
        print(f"Last call:  r3=0x{vdswap_calls[-1][0]} r4=0x{vdswap_calls[-1][1]} r5=0x{vdswap_calls[-1][2]}")
        
        # Check for unusual patterns
        unique_r3 = set(r3 for r3, _, _ in vdswap_calls)
        if len(unique_r3) > 1:
            print(f"WARNING: r3 parameter varies ({len(unique_r3)} unique values)")
            print(f"  Values: {', '.join(f'0x{v}' for v in list(unique_r3)[:5])}")
    else:
        print("No VdSwap calls found")
    
    return vdswap_calls

def main():
    log_path = "Traces/mw05_host_trace.log"
    
    print("=" * 60)
    print("MW05 No-Draw Analysis")
    print("=" * 60)
    
    try:
        # Run all analyses
        pm4_types = analyze_pm4_types(log_path)
        gfx_state = analyze_graphics_state(log_path)
        file_io, files = analyze_file_io(log_path)
        threads = analyze_thread_activity(log_path)
        vdswap = analyze_vdswap_pattern(log_path)
        
        # Summary
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)
        
        issues = []
        
        if not pm4_types:
            issues.append("❌ No PM4 packets found")
        else:
            print("✅ PM4 packets are being processed")
        
        if not gfx_state:
            issues.append("❌ No graphics state initialization found")
        else:
            print("✅ Some graphics state calls found")
        
        if not file_io:
            issues.append("❌ No file I/O found - resources not loading?")
        else:
            print("✅ File I/O is happening")
        
        if not vdswap:
            issues.append("❌ VdSwap not being called")
        else:
            print("✅ VdSwap is being called")
        
        if issues:
            print("\nPotential Issues:")
            for issue in issues:
                print(f"  {issue}")
        
        print("\n" + "=" * 60)
        
    except FileNotFoundError:
        print(f"ERROR: Log file not found: {log_path}")
        print("Run the game first with: powershell scripts/run_and_analyze.ps1")
        sys.exit(1)

if __name__ == "__main__":
    main()

