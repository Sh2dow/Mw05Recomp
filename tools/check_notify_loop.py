#!/usr/bin/env python3
"""Check what function is calling XNotifyGetNext in a loop."""

import requests
import json

def main():
    # Get disassembly around the call site
    url = "http://127.0.0.1:5050/disasm?ea=0x82849C00&count=50"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        print("\n=== DISASSEMBLY AROUND XNotifyGetNext CALL (0x82849C00) ===\n")
        
        for insn in data['disasm']:
            ea = int(insn['ea'], 16)
            text = insn['text']
            print(f"{ea:08X}  {text}")
        
        # Now get the decompiled code
        print("\n\n=== DECOMPILED CODE ===\n")
        
        # Find the function start (look for the function that contains 0x82849C28)
        # Try a few addresses before to find the function start
        for func_start in [0x82849C00, 0x82849B00, 0x82849A00, 0x82849900]:
            url2 = f"http://127.0.0.1:5050/decompile?ea={func_start:#x}"
            response2 = requests.get(url2)
            data2 = response2.json()
            
            if 'pseudocode' in data2 and data2['pseudocode']:
                print(f"\nFunction at {func_start:#x}:")
                print(data2['pseudocode'][:2000])  # First 2000 chars
                break
    
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()

