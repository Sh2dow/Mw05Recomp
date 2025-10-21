#!/usr/bin/env python3
"""
Analyze static constructor function pointer tables.
Fetches the tables from IDA Pro and identifies which constructors are being called.
"""

import requests
import struct
import sys

IDA_SERVER = "http://127.0.0.1:5050"

def fetch_bytes(ea, count):
    """Fetch raw bytes from IDA Pro HTTP server."""
    try:
        response = requests.get(f"{IDA_SERVER}/bytes?ea={ea:#x}&count={count}")
        response.raise_for_status()
        data = response.json()
        bytes_hex = data['bytes_hex']
        return bytes.fromhex(bytes_hex)
    except Exception as e:
        print(f"Error fetching bytes at {ea:#x}: {e}", file=sys.stderr)
        return None

def parse_function_table(data, base_ea):
    """Parse a function pointer table (big-endian uint32 values)."""
    functions = []
    for i in range(0, len(data), 4):
        # Big-endian uint32
        addr = struct.unpack('>I', data[i:i+4])[0]
        if addr != 0:
            functions.append((base_ea + i, addr))
    return functions

def main():
    print("=== Static Constructor Function Pointer Tables ===\n")
    
    # Table 1: 0x828DF0FC to 0x828DF108 (12 bytes = 3 pointers)
    print("Table 1: 0x828DF0FC - 0x828DF108 (3 pointers)")
    table1_data = fetch_bytes(0x828DF0FC, 12)
    if table1_data:
        table1_funcs = parse_function_table(table1_data, 0x828DF0FC)
        for offset, addr in table1_funcs:
            print(f"  {offset:#010x}: 0x{addr:08X}")
        print(f"  Total: {len(table1_funcs)} non-null pointers\n")
    
    # Table 2: 0x828D0010 to 0x828DF0F8 (0xF0E8 bytes = 61,674 bytes = 15,418 pointers)
    # This is a HUGE table, let's just fetch the first 1024 bytes (256 pointers)
    print("Table 2: 0x828D0010 - 0x828DF0F8 (first 256 pointers)")
    table2_data = fetch_bytes(0x828D0010, 1024)
    if table2_data:
        table2_funcs = parse_function_table(table2_data, 0x828D0010)
        for offset, addr in table2_funcs[:20]:  # Show first 20 non-null
            print(f"  {offset:#010x}: 0x{addr:08X}")
        if len(table2_funcs) > 20:
            print(f"  ... ({len(table2_funcs) - 20} more non-null pointers)")
        print(f"  Total (first 256): {len(table2_funcs)} non-null pointers\n")
    
    # Now let's try to identify which constructor is hanging
    # We can add instrumentation to sub_8262FC50 to log each function call
    print("\n=== Recommendation ===")
    print("To identify the hanging constructor:")
    print("1. Add a PPC_FUNC wrapper for sub_8262FC50 that:")
    print("   - Iterates through the tables manually")
    print("   - Logs each function pointer before calling it")
    print("   - Calls each function with a timeout or skip mechanism")
    print("2. This will show us exactly which constructor is hanging")
    print("3. Then we can skip ONLY that constructor instead of the entire function")

if __name__ == "__main__":
    main()

