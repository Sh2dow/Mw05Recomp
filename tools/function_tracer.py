#!/usr/bin/env python3
"""
Function tracer tool for MW05 recompiled code.

This tool helps identify which guest functions are being called and in what order,
to help diagnose blocking points in the game execution.
"""

import re
import sys
from pathlib import Path
from typing import List, Set, Dict
import json

class FunctionTracer:
    def __init__(self, ppc_dir: Path):
        self.ppc_dir = ppc_dir
        self.functions = {}  # address -> function_name
        self.function_files = {}  # address -> file_path
        
    def scan_functions(self):
        """Scan all PPC recompiled files to find function definitions."""
        print(f"[*] Scanning PPC directory: {self.ppc_dir}")
        
        ppc_files = sorted(self.ppc_dir.glob("ppc_recomp.*.cpp"))
        print(f"[*] Found {len(ppc_files)} PPC files")
        
        for ppc_file in ppc_files:
            self._scan_file(ppc_file)
        
        print(f"[*] Found {len(self.functions)} functions")
        return self.functions
    
    def _scan_file(self, file_path: Path):
        """Scan a single PPC file for function definitions."""
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Find function definitions: void sub_XXXXXXXX(PPCContext& ctx, uint8_t* base)
        pattern = r'void\s+(sub_[0-9A-Fa-f]{8})\s*\(PPCContext&\s+ctx,\s+uint8_t\*\s+base\)'
        matches = re.finditer(pattern, content)
        
        for match in matches:
            func_name = match.group(1)
            # Extract address from function name
            addr_str = func_name.replace('sub_', '')
            addr = int(addr_str, 16)
            
            self.functions[addr] = func_name
            self.function_files[addr] = file_path
    
    def find_function_calls(self, target_addr: int) -> List[int]:
        """Find all functions that call the target function."""
        print(f"[*] Finding callers of {self.functions.get(target_addr, f'0x{target_addr:08X}')}")
        
        callers = []
        target_name = self.functions.get(target_addr, f'sub_{target_addr:08X}')
        
        # Search all PPC files for calls to this function
        ppc_files = sorted(self.ppc_dir.glob("ppc_recomp.*.cpp"))
        
        for ppc_file in ppc_files:
            with open(ppc_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Find calls: target_name(ctx, base)
            if f'{target_name}(ctx, base)' in content:
                # Find which function this call is in
                # Look for the function definition before this call
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if f'{target_name}(ctx, base)' in line:
                        # Search backwards for function definition
                        for j in range(i, -1, -1):
                            func_match = re.match(r'void\s+(sub_[0-9A-Fa-f]{8})\s*\(', lines[j])
                            if func_match:
                                caller_name = func_match.group(1)
                                caller_addr = int(caller_name.replace('sub_', ''), 16)
                                if caller_addr not in callers:
                                    callers.append(caller_addr)
                                break
        
        print(f"[*] Found {len(callers)} callers")
        for caller_addr in callers:
            print(f"    - {self.functions.get(caller_addr, f'0x{caller_addr:08X}')}")
        
        return callers
    
    def trace_call_chain(self, target_addr: int, max_depth: int = 5) -> Dict:
        """Build a call chain tree for the target function."""
        print(f"[*] Building call chain for {self.functions.get(target_addr, f'0x{target_addr:08X}')}")
        
        def build_tree(addr: int, depth: int, visited: Set[int]) -> Dict:
            if depth >= max_depth or addr in visited:
                return {'address': addr, 'name': self.functions.get(addr, f'0x{addr:08X}'), 'callers': []}
            
            visited.add(addr)
            callers = self.find_function_calls(addr)
            
            tree = {
                'address': addr,
                'name': self.functions.get(addr, f'0x{addr:08X}'),
                'callers': [build_tree(caller, depth + 1, visited.copy()) for caller in callers]
            }
            
            return tree
        
        tree = build_tree(target_addr, 0, set())
        return tree
    
    def find_audio_registration_path(self):
        """Find the call path to audio registration function."""
        print("\n[*] Searching for audio registration function...")
        
        # sub_8285BC80 is the audio registration function
        audio_reg_addr = 0x8285BC80
        
        if audio_reg_addr not in self.functions:
            print(f"[!] Audio registration function not found in recompiled code")
            return None
        
        print(f"[+] Found audio registration function: {self.functions[audio_reg_addr]}")
        
        # Build call chain
        call_chain = self.trace_call_chain(audio_reg_addr, max_depth=3)
        
        return call_chain
    
    def print_call_tree(self, tree: Dict, indent: int = 0):
        """Print a call tree in a readable format."""
        prefix = "  " * indent
        print(f"{prefix}{tree['name']} (0x{tree['address']:08X})")
        
        if tree['callers']:
            print(f"{prefix}  Called by:")
            for caller in tree['callers']:
                self.print_call_tree(caller, indent + 2)

def main():
    # Default PPC directory
    ppc_dir = Path("Mw05RecompLib/ppc")
    
    if len(sys.argv) > 1:
        ppc_dir = Path(sys.argv[1])
    
    print("=" * 80)
    print("MW05 Function Tracer - Call Chain Analysis")
    print("=" * 80)
    
    tracer = FunctionTracer(ppc_dir)
    
    # Scan all functions
    tracer.scan_functions()
    
    # Find audio registration call path
    print("\n" + "=" * 80)
    print("Audio Registration Call Path Analysis")
    print("=" * 80)
    
    call_tree = tracer.find_audio_registration_path()
    
    if call_tree:
        print("\n[*] Call Tree:")
        tracer.print_call_tree(call_tree)
        
        # Save to JSON
        output_file = Path("out/build/x64-Clang-Debug/Mw05Recomp/audio_registration_call_tree.json")
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(call_tree, f, indent=2)
        print(f"\n[+] Call tree saved to: {output_file}")
    
    # Find specific functions of interest
    print("\n" + "=" * 80)
    print("Functions of Interest")
    print("=" * 80)
    
    interesting_addrs = [
        0x8285BC80,  # Audio registration
        0x82441CF0,  # Main game loop
        0x8262DE60,  # Frame update
        0x8262DD80,  # String formatting (where main thread is stuck)
    ]
    
    for addr in interesting_addrs:
        if addr in tracer.functions:
            print(f"\n[+] {tracer.functions[addr]} (0x{addr:08X})")
            print(f"    File: {tracer.function_files[addr].name}")
            callers = tracer.find_function_calls(addr)
            if callers:
                print(f"    Called by {len(callers)} functions")
            else:
                print(f"    [!] NEVER CALLED - This is a blocked code path!")
    
    print("\n" + "=" * 80)
    print("Analysis Complete!")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

