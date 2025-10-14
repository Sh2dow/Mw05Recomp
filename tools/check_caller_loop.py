#!/usr/bin/env python3
"""Check what's calling sub_82849BF8 in a loop."""

import requests

def main():
    # Get disassembly around 0x82849D98
    url = "http://127.0.0.1:5050/disasm?ea=0x82849D80&count=50"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        print("\n=== DISASSEMBLY AROUND 0x82849D98 ===\n")
        
        for insn in data['disasm']:
            ea = int(insn['ea'], 16)
            text = insn['text']
            marker = ">>> " if ea == 0x82849D98 else "    "
            print(f"{marker}{ea:08X}  {text}")
        
        # Now get the decompiled code for the function containing 0x82849D98
        print("\n\n=== DECOMPILED CODE FOR FUNCTION CONTAINING 0x82849D98 ===\n")
        
        url2 = "http://127.0.0.1:5050/decompile?ea=0x82849D80"
        response2 = requests.get(url2)
        data2 = response2.json()
        
        if 'pseudocode' in data2 and data2['pseudocode']:
            print(data2['pseudocode'])
    
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    main()

