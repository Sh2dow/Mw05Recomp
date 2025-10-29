#!/usr/bin/env python3
"""
Analyze_Function_List.py - Analyze and compare function lists in TOML files

This script helps understand the difference between MW05's massive function list
and UnleashedRecomp's minimal approach.

Usage:
    python Analyze_Function_List.py <toml_file> [--compare <other_toml>]

Example:
    python Analyze_Function_List.py Mw05RecompLib/config/MW05.toml
    python Analyze_Function_List.py Mw05RecompLib/config/MW05.toml --compare Mw05RecompLib/config/MW05_minimal.toml
"""

import sys
import re
from pathlib import Path
from collections import defaultdict

def parse_toml_functions(toml_path):
    """Parse functions from TOML file"""
    print(f"[*] Parsing: {toml_path}")
    
    functions = []
    
    # Pattern to match function entries
    func_pattern = re.compile(r'\{\s*address\s*=\s*0x([0-9A-Fa-f]+)\s*,\s*size\s*=\s*0x([0-9A-Fa-f]+)\s*\}')
    
    try:
        with open(toml_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        for match in func_pattern.finditer(content):
            addr = int(match.group(1), 16)
            size = int(match.group(2), 16)
            functions.append((addr, size))
    
    except FileNotFoundError:
        print(f"[!] Error: File not found: {toml_path}")
        return []
    
    print(f"[+] Found {len(functions)} functions")
    return functions

def analyze_functions(functions, name="Functions"):
    """Analyze function statistics"""
    if not functions:
        print(f"[!] No functions to analyze")
        return
    
    print()
    print("=" * 70)
    print(f"{name} Analysis")
    print("=" * 70)
    
    # Basic stats
    total = len(functions)
    addresses = [f[0] for f in functions]
    sizes = [f[1] for f in functions]
    
    print(f"Total functions: {total:,}")
    print()
    
    # Address range
    min_addr = min(addresses)
    max_addr = max(addresses)
    print(f"Address range:")
    print(f"  Min: 0x{min_addr:08X}")
    print(f"  Max: 0x{max_addr:08X}")
    print(f"  Span: 0x{max_addr - min_addr:08X} ({(max_addr - min_addr) / 1024 / 1024:.2f} MB)")
    print()
    
    # Size statistics
    min_size = min(sizes)
    max_size = max(sizes)
    avg_size = sum(sizes) / len(sizes)
    total_size = sum(sizes)
    
    print(f"Size statistics:")
    print(f"  Min: 0x{min_size:X} ({min_size} bytes)")
    print(f"  Max: 0x{max_size:X} ({max_size} bytes)")
    print(f"  Avg: 0x{int(avg_size):X} ({int(avg_size)} bytes)")
    print(f"  Total: 0x{total_size:X} ({total_size / 1024 / 1024:.2f} MB)")
    print()
    
    # Size distribution
    size_buckets = defaultdict(int)
    for size in sizes:
        if size < 0x40:
            size_buckets['< 0x40 (tiny)'] += 1
        elif size < 0x100:
            size_buckets['0x40-0xFF (small)'] += 1
        elif size < 0x400:
            size_buckets['0x100-0x3FF (medium)'] += 1
        elif size < 0x1000:
            size_buckets['0x400-0xFFF (large)'] += 1
        else:
            size_buckets['>= 0x1000 (huge)'] += 1
    
    print("Size distribution:")
    for bucket in ['< 0x40 (tiny)', '0x40-0xFF (small)', '0x100-0x3FF (medium)', 
                   '0x400-0xFFF (large)', '>= 0x1000 (huge)']:
        count = size_buckets[bucket]
        pct = (count / total) * 100
        print(f"  {bucket:20s}: {count:6,} ({pct:5.1f}%)")
    print()
    
    # Alignment check
    aligned_16 = sum(1 for addr in addresses if addr % 16 == 0)
    aligned_4 = sum(1 for addr in addresses if addr % 4 == 0)
    
    print("Alignment:")
    print(f"  16-byte aligned: {aligned_16:,} ({aligned_16/total*100:.1f}%)")
    print(f"  4-byte aligned:  {aligned_4:,} ({aligned_4/total*100:.1f}%)")
    print()

def compare_functions(funcs1, funcs2, name1="Set 1", name2="Set 2"):
    """Compare two function sets"""
    print()
    print("=" * 70)
    print(f"Comparison: {name1} vs {name2}")
    print("=" * 70)
    
    addrs1 = set(f[0] for f in funcs1)
    addrs2 = set(f[0] for f in funcs2)
    
    only_in_1 = addrs1 - addrs2
    only_in_2 = addrs2 - addrs1
    common = addrs1 & addrs2
    
    print(f"Functions only in {name1}: {len(only_in_1):,}")
    print(f"Functions only in {name2}: {len(only_in_2):,}")
    print(f"Common functions: {len(common):,}")
    print()
    
    if only_in_2:
        print(f"Sample of functions only in {name2} (first 10):")
        for addr in sorted(only_in_2)[:10]:
            print(f"  0x{addr:08X}")
        if len(only_in_2) > 10:
            print(f"  ... and {len(only_in_2) - 10} more")
        print()

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    toml1 = sys.argv[1]
    toml2 = None
    
    # Check for --compare flag
    if '--compare' in sys.argv:
        idx = sys.argv.index('--compare')
        if idx + 1 < len(sys.argv):
            toml2 = sys.argv[idx + 1]
    
    print("=" * 70)
    print("MW05 Function List Analyzer")
    print("=" * 70)
    print()
    
    # Parse first TOML
    funcs1 = parse_toml_functions(toml1)
    if funcs1:
        analyze_functions(funcs1, Path(toml1).name)
    
    # Parse and compare second TOML if provided
    if toml2:
        funcs2 = parse_toml_functions(toml2)
        if funcs2:
            analyze_functions(funcs2, Path(toml2).name)
        
        if funcs1 and funcs2:
            compare_functions(funcs1, funcs2, Path(toml1).name, Path(toml2).name)
    
    # Recommendations
    print()
    print("=" * 70)
    print("Recommendations")
    print("=" * 70)
    print()
    
    if funcs1 and len(funcs1) > 1000:
        print("[!] WARNING: Very large function list detected!")
        print()
        print("UnleashedRecomp uses only ~43 functions (problematic switch tables).")
        print("MW05 currently has 24,000+ functions, which may cause:")
        print("  - Slow compilation times")
        print("  - Initialization delays")
        print("  - Potential stability issues")
        print()
        print("Recommended approach:")
        print("  1. Extract minimal function list from recompiler errors:")
        print("     python tools/Extract_Minimal_Functions.py <build_log> MW05_minimal.toml")
        print()
        print("  2. Backup current MW05.toml:")
        print("     copy Mw05RecompLib/config/MW05.toml Mw05RecompLib/config/MW05_full.toml")
        print()
        print("  3. Replace with minimal list and test:")
        print("     copy MW05_minimal.toml Mw05RecompLib/config/MW05.toml")
        print("     .\\build_cmd.ps1 -Stage app")
        print()
    
    print("=" * 70)

if __name__ == '__main__':
    main()

