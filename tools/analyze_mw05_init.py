#!/usr/bin/env python3
"""
Analyze MW05 initialization sequence to find what's blocking rendering.

This script examines the host trace log to identify:
1. What initialization functions are called
2. What the game is waiting for
3. Missing prerequisites that prevent rendering from starting
"""

import re
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Set

class MW05InitAnalyzer:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.lines = []
        self.function_calls = []
        self.memory_regions = defaultdict(list)
        self.scheduler_states = []
        self.vblank_count = 0
        
    def load_log(self):
        """Load and parse the trace log."""
        print(f"Loading log from {self.log_path}...")
        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
        print(f"Loaded {len(self.lines)} lines")
        
    def extract_function_calls(self):
        """Extract all function calls from the log."""
        print("\nExtracting function calls...")
        
        # Pattern: import=HOST.FunctionName or import=HOST.sub_XXXXXXXX
        pattern = re.compile(r'import=HOST\.([^\s]+)')
        
        for i, line in enumerate(self.lines):
            match = pattern.search(line)
            if match:
                func_name = match.group(1)
                self.function_calls.append((i, func_name, line.strip()))
                
        print(f"Found {len(self.function_calls)} function calls")
        
    def analyze_initialization_sequence(self):
        """Analyze the initialization sequence to find key events."""
        print("\n=== INITIALIZATION SEQUENCE ===")
        
        # Key initialization functions to look for
        key_funcs = [
            'KiSystemStartup',
            'VideoDevice.ready',
            'ForceVD.init',
            'VdInitializeRingBuffer',
            'BuilderKick',
            'MW05.RegisterManualHooks',
            'VblankPump.start',
            'VdCallGraphicsNotificationRoutines',
        ]
        
        for func in key_funcs:
            matches = [(i, line) for i, name, line in self.function_calls if func in name]
            if matches:
                print(f"\n{func}:")
                for i, line in matches[:3]:  # Show first 3 occurrences
                    print(f"  Line {i+1}: {line[:120]}")
            else:
                print(f"\n{func}: NOT FOUND")
                
    def find_scheduler_context_accesses(self):
        """Find all accesses to the scheduler context at 0x00060E30."""
        print("\n=== SCHEDULER CONTEXT (0x00060E30) ===")
        
        pattern = re.compile(r'00060E[0-9A-F]{2}')
        matches = []
        
        for i, line in enumerate(self.lines):
            if pattern.search(line):
                matches.append((i, line.strip()))
                
        print(f"Found {len(matches)} references to scheduler context")
        if matches:
            print("\nFirst 10 references:")
            for i, line in matches[:10]:
                print(f"  Line {i+1}: {line[:150]}")
                
    def find_memory_writes(self):
        """Look for patterns that might indicate memory writes."""
        print("\n=== LOOKING FOR MEMORY WRITE PATTERNS ===")
        
        # Look for allocator calls
        alloc_pattern = re.compile(r'MW05HostAllocCb|alloc.*ret=')
        alloc_calls = []
        
        for i, line in enumerate(self.lines):
            if alloc_pattern.search(line):
                alloc_calls.append((i, line.strip()))
                
        print(f"Found {len(alloc_calls)} allocator-related calls")
        if alloc_calls:
            print("\nAllocator calls:")
            for i, line in alloc_calls[:20]:
                print(f"  Line {i+1}: {line[:150]}")
                
    def find_pm4_builder_calls(self):
        """Look for PM4 builder function calls."""
        print("\n=== PM4 BUILDER FUNCTION CALLS ===")
        
        builder_addrs = [
            '825972B0',  # Main PM4 builder
            '82595FC8',  # Pre-present helper
            '82596E40',  # Builder variant
            '825968B0',  # Builder variant
        ]
        
        for addr in builder_addrs:
            pattern = re.compile(f'sub_{addr}|{addr}')
            matches = [(i, line) for i, line in enumerate(self.lines) if pattern.search(line)]
            
            if matches:
                print(f"\n0x{addr}:")
                for i, line in matches[:5]:
                    print(f"  Line {i+1}: {line.strip()[:150]}")
            else:
                print(f"\n0x{addr}: NEVER CALLED")
                
    def find_render_draw_calls(self):
        """Look for render/draw function calls."""
        print("\n=== RENDER/DRAW FUNCTION CALLS ===")
        
        render_funcs = [
            ('82BDD9F0', 'SetRenderTarget'),
            ('82BDDD38', 'SetDepthStencilSurface'),
            ('82BFE4C8', 'Clear'),
            ('82BE5900', 'DrawPrimitive'),
            ('82BE5CF0', 'DrawIndexedPrimitive'),
        ]
        
        for addr, name in render_funcs:
            pattern = re.compile(f'sub_{addr}|{addr}')
            matches = [(i, line) for i, line in enumerate(self.lines) if pattern.search(line)]
            
            if matches:
                print(f"\n{name} (0x{addr}):")
                for i, line in matches[:3]:
                    print(f"  Line {i+1}: {line.strip()[:150]}")
            else:
                print(f"\n{name} (0x{addr}): NEVER CALLED")
                
    def count_vblanks(self):
        """Count vblank interrupts to see how long the game ran."""
        print("\n=== VBLANK ANALYSIS ===")
        
        vblank_pattern = re.compile(r'VblankPump\.host_isr|nudge\.vblank')
        self.vblank_count = sum(1 for line in self.lines if vblank_pattern.search(line))
        
        print(f"Total vblanks: {self.vblank_count}")
        print(f"Approximate runtime: {self.vblank_count / 60:.1f} seconds (at 60Hz)")
        
    def find_waiting_patterns(self):
        """Look for patterns that suggest the game is waiting for something."""
        print("\n=== WAITING/BLOCKING PATTERNS ===")
        
        # Look for repeated patterns that might indicate polling/waiting
        wait_patterns = [
            'Wait',
            'Sleep',
            'Event',
            'Signal',
            'Mutex',
            'Semaphore',
            'KeWait',
            'NtWait',
        ]
        
        for pattern in wait_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = [(i, line) for i, line in enumerate(self.lines) if regex.search(line)]
            
            if matches:
                print(f"\n{pattern}: {len(matches)} occurrences")
                # Show first few unique lines
                unique_lines = []
                seen = set()
                for i, line in matches:
                    key = line[:80]  # Use first 80 chars as key
                    if key not in seen:
                        seen.add(key)
                        unique_lines.append((i, line))
                        if len(unique_lines) >= 3:
                            break
                            
                for i, line in unique_lines:
                    print(f"  Line {i+1}: {line.strip()[:150]}")
                    
    def find_file_io(self):
        """Look for file I/O operations."""
        print("\n=== FILE I/O OPERATIONS ===")
        
        io_patterns = [
            'NtCreateFile',
            'NtOpenFile',
            'NtReadFile',
            'XamContentCreate',
            'XamRootCreate',
        ]
        
        for pattern in io_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = [(i, line) for i, line in enumerate(self.lines) if regex.search(line)]
            
            if matches:
                print(f"\n{pattern}: {len(matches)} calls")
                for i, line in matches[:5]:
                    print(f"  Line {i+1}: {line.strip()[:150]}")
                    
    def analyze(self):
        """Run all analysis steps."""
        self.load_log()
        self.extract_function_calls()
        self.analyze_initialization_sequence()
        self.find_scheduler_context_accesses()
        self.find_memory_writes()
        self.find_pm4_builder_calls()
        self.find_render_draw_calls()
        self.count_vblanks()
        self.find_waiting_patterns()
        self.find_file_io()
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)

def main():
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    else:
        # Default to the debug build log
        log_path = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
        
    if not Path(log_path).exists():
        print(f"Error: Log file not found: {log_path}")
        print(f"Usage: {sys.argv[0]} [log_path]")
        sys.exit(1)
        
    analyzer = MW05InitAnalyzer(log_path)
    analyzer.analyze()

if __name__ == "__main__":
    main()

