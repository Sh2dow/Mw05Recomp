#!/usr/bin/env python3
"""
Analyze PM4 command building and processing in MW05.

This script examines what PM4 commands are being built and why they're not being processed.
"""

import re
import sys
from pathlib import Path
from collections import defaultdict

class PM4CommandAnalyzer:
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.lines = []
        
    def load_log(self):
        """Load the trace log."""
        print(f"Loading log from {self.log_path}...")
        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
        print(f"Loaded {len(self.lines)} lines\n")
        
    def analyze_builder_calls(self):
        """Analyze PM4 builder function calls in detail."""
        print("="*80)
        print("PM4 BUILDER CALLS (0x825972B0)")
        print("="*80)
        
        # Find all calls to 0x825972B0
        builder_pattern = re.compile(r'sub_825972B0|825972B0')
        
        builder_sections = []
        current_section = []
        
        for i, line in enumerate(self.lines):
            if builder_pattern.search(line):
                if 'sub_825972B0.lr=' in line:
                    # Start of new builder call
                    if current_section:
                        builder_sections.append(current_section)
                    current_section = [(i, line.strip())]
                else:
                    current_section.append((i, line.strip()))
            elif current_section and len(current_section) < 50:
                # Collect context after builder call
                if any(keyword in line for keyword in ['825972B0', 'Sched', 'alloc', 'BuilderKick']):
                    current_section.append((i, line.strip()))
                    
        if current_section:
            builder_sections.append(current_section)
            
        print(f"\nFound {len(builder_sections)} PM4 builder call sequences\n")
        
        # Show first few builder calls in detail
        for idx, section in enumerate(builder_sections[:5]):
            print(f"\n--- Builder Call #{idx+1} ---")
            for line_num, line in section[:20]:
                print(f"  {line_num+1:6d}: {line[:140]}")
                
    def analyze_scheduler_state(self):
        """Analyze scheduler state changes."""
        print("\n" + "="*80)
        print("SCHEDULER STATE CHANGES")
        print("="*80)
        
        # Look for scheduler state dumps
        sched_pattern = re.compile(r'Sched\.825972B0|BuilderKick\.seed|qhead=|qtail=')
        
        matches = []
        for i, line in enumerate(self.lines):
            if sched_pattern.search(line):
                matches.append((i, line.strip()))
                
        print(f"\nFound {len(matches)} scheduler state references\n")
        
        # Show key state changes
        print("Key scheduler state changes:")
        for i, line in matches[:30]:
            print(f"  {i+1:6d}: {line[:140]}")
            
    def analyze_pm4_buffer_content(self):
        """Look for actual PM4 command content in buffers."""
        print("\n" + "="*80)
        print("PM4 BUFFER CONTENT")
        print("="*80)
        
        # Look for non-zero PM4 headers
        type3_pattern = re.compile(r'TYPE3.*header=(?!00000000)')
        type0_pattern = re.compile(r'TYPE0.*header=(?!00000000)')
        
        type3_matches = [(i, line.strip()) for i, line in enumerate(self.lines) if type3_pattern.search(line)]
        type0_matches = [(i, line.strip()) for i, line in enumerate(self.lines) if type0_pattern.search(line)]
        
        print(f"\nNon-zero TYPE3 headers: {len(type3_matches)}")
        print(f"Non-zero TYPE0 headers: {len(type0_matches)}")
        
        if type3_matches:
            print("\nFirst TYPE3 commands:")
            for i, line in type3_matches[:10]:
                print(f"  {i+1:6d}: {line[:140]}")
                
        if type0_matches:
            print("\nFirst TYPE0 commands:")
            for i, line in type0_matches[:10]:
                print(f"  {i+1:6d}: {line[:140]}")
                
    def analyze_micro_ib(self):
        """Analyze MW05 micro-IB activity."""
        print("\n" + "="*80)
        print("MW05 MICRO-IB ACTIVITY")
        print("="*80)
        
        micro_pattern = re.compile(r'MW05.*[Mm]icro|MicroIB|micro.*tree|GLAC|magic.*MW05')
        
        matches = [(i, line.strip()) for i, line in enumerate(self.lines) if micro_pattern.search(line)]
        
        print(f"\nFound {len(matches)} micro-IB related messages\n")
        
        if matches:
            print("Micro-IB activity:")
            for i, line in matches[:30]:
                print(f"  {i+1:6d}: {line[:140]}")
                
    def find_command_submission(self):
        """Look for where commands are submitted to GPU."""
        print("\n" + "="*80)
        print("COMMAND SUBMISSION TO GPU")
        print("="*80)
        
        submit_patterns = [
            'VdSwap',
            'kick',
            'submit',
            'wptr',
            'rptr',
            'RB.rptr',
            'RB.wptr',
        ]
        
        for pattern in submit_patterns:
            regex = re.compile(pattern, re.IGNORECASE)
            matches = [(i, line.strip()) for i, line in enumerate(self.lines) if regex.search(line)]
            
            if matches:
                print(f"\n{pattern}: {len(matches)} occurrences")
                # Show first few
                for i, line in matches[:5]:
                    print(f"  {i+1:6d}: {line[:140]}")
                    
    def analyze_queue_pointers(self):
        """Analyze queue head/tail pointer changes."""
        print("\n" + "="*80)
        print("QUEUE POINTER ANALYSIS")
        print("="*80)
        
        # Extract qhead and qtail values
        queue_pattern = re.compile(r'qhead=([0-9A-F]{8}).*qtail=([0-9A-F]{8})')
        
        queue_states = []
        for i, line in enumerate(self.lines):
            match = queue_pattern.search(line)
            if match:
                qhead = match.group(1)
                qtail = match.group(2)
                queue_states.append((i, qhead, qtail, line.strip()))
                
        print(f"\nFound {len(queue_states)} queue state snapshots\n")
        
        if queue_states:
            print("Queue pointer evolution:")
            for i, qhead, qtail, line in queue_states[:20]:
                print(f"  {i+1:6d}: qhead={qhead} qtail={qtail}")
                if qhead != qtail:
                    print(f"         ^ QUEUE NOT EMPTY! {int(qtail, 16) - int(qhead, 16)} bytes")
                    
    def analyze(self):
        """Run all analysis."""
        self.load_log()
        self.analyze_builder_calls()
        self.analyze_scheduler_state()
        self.analyze_queue_pointers()
        self.analyze_pm4_buffer_content()
        self.analyze_micro_ib()
        self.find_command_submission()
        
        print("\n" + "="*80)
        print("ANALYSIS COMPLETE")
        print("="*80)

def main():
    if len(sys.argv) > 1:
        log_path = sys.argv[1]
    else:
        log_path = "out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log"
        
    if not Path(log_path).exists():
        print(f"Error: Log file not found: {log_path}")
        sys.exit(1)
        
    analyzer = PM4CommandAnalyzer(log_path)
    analyzer.analyze()

if __name__ == "__main__":
    main()

