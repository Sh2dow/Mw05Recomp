#!/usr/bin/env python3
"""
Analyze static initializer table from IDA dumps
"""

import json
import struct

def parse_hex_to_pointers(hex_str):
    """Parse hex string to list of 32-bit big-endian pointers"""
    bytes_data = bytes.fromhex(hex_str)
    pointers = []
    for i in range(0, len(bytes_data), 4):
        if i + 4 <= len(bytes_data):
            # Big-endian 32-bit integer
            ptr = struct.unpack('>I', bytes_data[i:i+4])[0]
            pointers.append(ptr)
    return pointers

def main():
    print("=== Static Initializer Table Analysis ===\n")
    
    # Load table 2 (the main one with function pointers)
    with open('IDA_dumps/static_init_table2.json', 'r') as f:
        table2 = json.load(f)
    
    print(f"Table 2 Address: {table2['ea']}")
    print(f"Table 2 Size: {table2['size']} bytes")
    print(f"Table 2 Hex: {table2['bytes_hex']}\n")
    
    pointers = parse_hex_to_pointers(table2['bytes_hex'])
    
    print("Function Pointers in Table:")
    for i, ptr in enumerate(pointers):
        offset = i * 4
        addr = int(table2['ea'], 16) + offset
        if ptr == 0:
            print(f"  [{i}] @ 0x{addr:08X}: 0x{ptr:08X} (NULL)")
        elif ptr == 0xFFFFFFFF:
            print(f"  [{i}] @ 0x{addr:08X}: 0x{ptr:08X} (END MARKER)")
        elif 0x82000000 <= ptr <= 0x82CD0000:
            print(f"  [{i}] @ 0x{addr:08X}: 0x{ptr:08X} (VALID)")
        else:
            print(f"  [{i}] @ 0x{addr:08X}: 0x{ptr:08X} (INVALID - outside XEX range!)")
    
    print("\n=== Analysis ===")
    valid_count = sum(1 for p in pointers if 0x82000000 <= p <= 0x82CD0000 and p != 0 and p != 0xFFFFFFFF)
    null_count = sum(1 for p in pointers if p == 0)
    invalid_count = sum(1 for p in pointers if p != 0 and p != 0xFFFFFFFF and not (0x82000000 <= p <= 0x82CD0000))
    
    print(f"Total pointers: {len(pointers)}")
    print(f"Valid pointers: {valid_count}")
    print(f"NULL pointers: {null_count}")
    print(f"Invalid pointers: {invalid_count}")
    
    if invalid_count > 0:
        print("\n⚠️  WARNING: Table contains invalid pointers!")
        print("This suggests the table is corrupted or not properly loaded.")
    else:
        print("\n✅ All pointers are valid!")
        print("The table in IDA is correct. The issue is at runtime.")

if __name__ == '__main__':
    main()

