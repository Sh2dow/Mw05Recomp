#!/usr/bin/env python3
"""Find the caller of sub_82849BF8 to see if there's a loop."""

import requests

def main():
    # Search for calls to 0x82849BF8 in the generated code
    print("\n=== SEARCHING FOR CALLS TO sub_82849BF8 (0x82849BF8) ===\n")
    
    # Get decompiled code for a few functions that might call it
    # Try addresses around 0x82849BF8
    for func_addr in [0x82849D00, 0x82849E00, 0x82849F00, 0x8284A000]:
        url = f"http://127.0.0.1:5050/decompile?ea={func_addr:#x}"
        try:
            response = requests.get(url)
            data = response.json()
            
            if 'pseudocode' in data and data['pseudocode']:
                code = data['pseudocode']
                # Check if it calls sub_82849BF8
                if '82849BF8' in code or '82849bf8' in code.lower():
                    print(f"\n=== FUNCTION AT {func_addr:#x} CALLS sub_82849BF8 ===\n")
                    print(code[:3000])  # First 3000 chars
                    print("\n" + "="*80 + "\n")
        except Exception as e:
            pass
    
    # Also check the disassembly to find who calls 0x82849BF8
    print("\n=== CHECKING DISASSEMBLY FOR CALLS TO 0x82849BF8 ===\n")
    
    # Search backwards from 0x82849BF8
    for search_addr in [0x82849B00, 0x82849A00, 0x82849900, 0x82849800]:
        url = f"http://127.0.0.1:5050/disasm?ea={search_addr:#x}&count=100"
        try:
            response = requests.get(url)
            data = response.json()
            
            for insn in data['disasm']:
                ea = int(insn['ea'], 16)
                text = insn['text']
                
                # Check for bl (branch and link) to 0x82849BF8
                if 'bl' in text.lower() and ('82849bf8' in text.lower() or '82849BF8' in text):
                    print(f"{ea:08X}  {text}  <-- CALLS sub_82849BF8")
        except Exception as e:
            pass

if __name__ == "__main__":
    main()

