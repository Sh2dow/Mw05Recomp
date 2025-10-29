#!/usr/bin/env python3
"""
Extract_Minimal_Functions.py - Extract only mandatory functions for MW05 recompilation

This script follows UnleashedRecomp's approach: only declare functions that have
jump tables or other issues that prevent proper analysis by the recompiler.

Usage:
    python Extract_Minimal_Functions.py <recomp_log> <output_toml> [options]

Options:
    --min-size 0xNN         Minimum function size (default: 0x20)
    --max-size 0xNN         Maximum function size (default: 0x4000)
    --enforce-align         Require 0x10 alignment
    --addr-range 0xLOW-0xHI Address range filter
    --batch-size N          Limit to first N functions by size

Example:
    python Extract_Minimal_Functions.py traces/build_log.txt Mw05RecompLib/config/MW05_minimal.toml --min-size 0x20 --max-size 0x4000
"""

import sys
import re
from pathlib import Path

def parse_args():
    """Parse command line arguments"""
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    
    config = {
        'recomp_log': sys.argv[1],
        'output_toml': sys.argv[2],
        'min_size': 0x20,
        'max_size': 0x4000,
        'enforce_align': False,
        'addr_range': None,
        'batch_size': None
    }
    
    i = 3
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--min-size' and i + 1 < len(sys.argv):
            config['min_size'] = int(sys.argv[i + 1], 16)
            i += 2
        elif arg == '--max-size' and i + 1 < len(sys.argv):
            config['max_size'] = int(sys.argv[i + 1], 16)
            i += 2
        elif arg == '--enforce-align':
            config['enforce_align'] = True
            i += 1
        elif arg == '--addr-range' and i + 1 < len(sys.argv):
            lo, hi = sys.argv[i + 1].split('-')
            config['addr_range'] = (int(lo, 16), int(hi, 16))
            i += 2
        elif arg == '--batch-size' and i + 1 < len(sys.argv):
            config['batch_size'] = int(sys.argv[i + 1])
            i += 2
        else:
            i += 1
    
    return config

def extract_switch_errors(log_path):
    """Extract addresses of functions with switch table errors from recompiler log"""
    print(f"[*] Parsing recompiler log: {log_path}")
    
    switch_patterns = [
        # XenonRecomp error patterns
        re.compile(r'ERROR:\s*Switch case at\s*(?:0x)?([0-9A-Fa-f]{6,8})', re.IGNORECASE),
        re.compile(r'(?:error|ERROR).*?(?:switch|Switch).*?(?:at|@)\s*(?:0x)?([0-9A-Fa-f]{6,8})'),
        re.compile(r'(?:warning|WARN).*?(?:switch|Switch).*?(?:at|@)\s*(?:0x)?([0-9A-Fa-f]{6,8})'),
        # Jump table patterns
        re.compile(r'(?:error|ERROR).*?(?:jump table|jumptable).*?(?:at|@)\s*(?:0x)?([0-9A-Fa-f]{6,8})', re.IGNORECASE),
        # Analysis failure patterns
        re.compile(r'(?:error|ERROR).*?(?:analyze|analysis).*?(?:at|@|function)\s*(?:0x)?([0-9A-Fa-f]{6,8})', re.IGNORECASE),
    ]
    
    addresses = set()
    
    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                for pattern in switch_patterns:
                    match = pattern.search(line)
                    if match:
                        addr = match.group(1).upper()
                        addresses.add(int(addr, 16))
                        break
    except FileNotFoundError:
        print(f"[!] Warning: Log file not found: {log_path}")
        print("[!] Will create empty functions list")
        return set()
    
    print(f"[+] Found {len(addresses)} problematic addresses")
    return addresses

def create_function_entries(addresses, config):
    """Create function entries with size estimation"""
    if not addresses:
        return []
    
    # Sort addresses
    sorted_addrs = sorted(addresses)
    
    functions = []
    for i, addr in enumerate(sorted_addrs):
        # Estimate size based on next function or use default
        if i + 1 < len(sorted_addrs):
            next_addr = sorted_addrs[i + 1]
            # Size is distance to next function minus padding
            size = max(0x20, next_addr - addr - 4)
        else:
            # Last function, use conservative default
            size = 0x100
        
        # Apply filters
        if size < config['min_size']:
            continue
        if size > config['max_size']:
            size = config['max_size']
        
        if config['enforce_align'] and (addr % 16) != 0:
            continue
        
        if config['addr_range']:
            lo, hi = config['addr_range']
            if not (lo <= addr <= hi):
                continue
        
        functions.append((addr, size))
    
    # Sort by size (smaller first - safer)
    functions.sort(key=lambda x: (x[1], x[0]))
    
    # Apply batch size limit
    if config['batch_size']:
        functions = functions[:config['batch_size']]
    
    print(f"[+] Created {len(functions)} function entries")
    if functions:
        print(f"    Address range: 0x{min(f[0] for f in functions):08X} - 0x{max(f[0] for f in functions):08X}")
        print(f"    Size range: 0x{min(f[1] for f in functions):X} - 0x{max(f[1] for f in functions):X}")
    
    return functions

def write_toml(functions, output_path):
    """Write functions to TOML format"""
    print(f"[*] Writing TOML to: {output_path}")
    
    lines = ["functions = ["]
    
    for addr, size in functions:
        lines.append(f"    {{ address = 0x{addr:08X}, size = 0x{size:X} }},")
    
    # Remove trailing comma from last entry
    if len(lines) > 1:
        lines[-1] = lines[-1].rstrip(',')
    
    lines.append("]")
    
    output = '\n'.join(lines)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output)
    
    print(f"[+] Wrote {len(functions)} functions to {output_path}")

def main():
    config = parse_args()
    
    print("=" * 70)
    print("MW05 Minimal Function Extractor")
    print("Following UnleashedRecomp's approach: only problematic functions")
    print("=" * 70)
    print()
    
    # Extract problematic addresses from recompiler log
    addresses = extract_switch_errors(config['recomp_log'])
    
    if not addresses:
        print()
        print("[!] No problematic functions found!")
        print("[!] This is GOOD - it means the recompiler can handle all functions.")
        print("[!] Creating empty functions list (like UnleashedRecomp with 43 functions).")
        print()
    
    # Create function entries
    functions = create_function_entries(addresses, config)
    
    # Write TOML
    write_toml(functions, config['output_toml'])
    
    print()
    print("=" * 70)
    print("Summary:")
    print(f"  Input log: {config['recomp_log']}")
    print(f"  Output TOML: {config['output_toml']}")
    print(f"  Functions extracted: {len(functions)}")
    print(f"  Min size: 0x{config['min_size']:X}")
    print(f"  Max size: 0x{config['max_size']:X}")
    if config['batch_size']:
        print(f"  Batch size limit: {config['batch_size']}")
    print()
    print("Next steps:")
    print("  1. Review the generated TOML file")
    print("  2. Update Mw05RecompLib/config/MW05.toml with minimal functions")
    print("  3. Rebuild with: .\\build_cmd.ps1 -Stage app")
    print("  4. Test with: python scripts/auto_handle_messageboxes.py --duration 30")
    print("=" * 70)

if __name__ == '__main__':
    main()

