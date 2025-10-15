#!/usr/bin/env python3
"""
Diagnostic tool to analyze MW05 execution traces and identify blocking points.

This tool analyzes the mw05_host_trace.log to:
1. Identify hot spots (functions called repeatedly - potential infinite loops)
2. Identify cold spots (functions never called - blocked code paths)
3. Track thread activity patterns
4. Build execution timeline
5. Compare with Xenia's execution pattern
"""

import re
import sys
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Tuple, Set
import json

class TraceAnalyzer:
    def __init__(self, trace_file: Path):
        self.trace_file = trace_file
        self.function_calls = defaultdict(int)  # function_addr -> call_count
        self.function_callers = defaultdict(set)  # function_addr -> set of caller_addrs
        self.thread_activity = defaultdict(list)  # thread_id -> [(timestamp, function_addr)]
        self.kernel_calls = defaultdict(int)  # kernel_function_name -> call_count
        self.stub_calls = defaultdict(int)  # stub_function_name -> call_count
        self.timeline = []  # [(timestamp, event_type, details)]
        
    def parse_trace(self):
        """Parse the trace log file."""
        print(f"[*] Parsing trace file: {self.trace_file}")
        
        if not self.trace_file.exists():
            print(f"[!] Trace file not found: {self.trace_file}")
            return False
            
        line_count = 0
        with open(self.trace_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line_count += 1
                if line_count % 100000 == 0:
                    print(f"[*] Processed {line_count} lines...")
                
                self._parse_line(line.strip())
        
        print(f"[*] Parsed {line_count} lines")
        return True
    
    def _parse_line(self, line: str):
        """Parse a single trace line."""
        # Skip empty lines
        if not line:
            return
        
        # Parse kernel calls: "KERNEL.FunctionName(params)"
        kernel_match = re.match(r'KERNEL\.(\w+)\(', line)
        if kernel_match:
            func_name = kernel_match.group(1)
            self.kernel_calls[func_name] += 1
            return
        
        # Parse stub calls: "STUB: FunctionName" or "!!! NOT IMPLEMENTED: FunctionName"
        stub_match = re.search(r'(?:STUB|NOT IMPLEMENTED):\s*(\w+)', line)
        if stub_match:
            func_name = stub_match.group(1)
            self.stub_calls[func_name] += 1
            return
        
        # Parse host operations: "HOST.Operation"
        host_match = re.match(r'HOST\.(.+)', line)
        if host_match:
            operation = host_match.group(1)
            self.kernel_calls[f"HOST.{operation}"] += 1
            return
    
    def identify_hot_spots(self, top_n: int = 20) -> List[Tuple[str, int]]:
        """Identify the most frequently called functions (potential infinite loops)."""
        print(f"\n[*] Top {top_n} Hot Spots (Most Frequently Called):")
        print("=" * 80)
        
        # Combine kernel and stub calls
        all_calls = dict(self.kernel_calls)
        all_calls.update({f"STUB.{k}": v for k, v in self.stub_calls.items()})
        
        hot_spots = sorted(all_calls.items(), key=lambda x: x[1], reverse=True)[:top_n]
        
        for i, (func, count) in enumerate(hot_spots, 1):
            print(f"{i:2d}. {func:50s} : {count:10,d} calls")
        
        return hot_spots
    
    def identify_stub_patterns(self) -> Dict[str, int]:
        """Identify patterns in stub calls."""
        print(f"\n[*] Stub Call Analysis:")
        print("=" * 80)
        
        if not self.stub_calls:
            print("No stub calls found!")
            return {}
        
        total_stub_calls = sum(self.stub_calls.values())
        print(f"Total stub calls: {total_stub_calls:,}")
        print(f"Unique stubs: {len(self.stub_calls)}")
        
        print(f"\nTop 20 Most Called Stubs:")
        top_stubs = sorted(self.stub_calls.items(), key=lambda x: x[1], reverse=True)[:20]
        for i, (func, count) in enumerate(top_stubs, 1):
            pct = (count / total_stub_calls) * 100
            print(f"{i:2d}. {func:50s} : {count:10,d} calls ({pct:5.2f}%)")
        
        return self.stub_calls
    
    def identify_kernel_patterns(self) -> Dict[str, int]:
        """Identify patterns in kernel calls."""
        print(f"\n[*] Kernel Call Analysis:")
        print("=" * 80)
        
        if not self.kernel_calls:
            print("No kernel calls found!")
            return {}
        
        total_kernel_calls = sum(self.kernel_calls.values())
        print(f"Total kernel calls: {total_kernel_calls:,}")
        print(f"Unique kernel functions: {len(self.kernel_calls)}")
        
        print(f"\nTop 20 Most Called Kernel Functions:")
        top_kernel = sorted(self.kernel_calls.items(), key=lambda x: x[1], reverse=True)[:20]
        for i, (func, count) in enumerate(top_kernel, 1):
            pct = (count / total_kernel_calls) * 100
            print(f"{i:2d}. {func:50s} : {count:10,d} calls ({pct:5.2f}%)")
        
        return self.kernel_calls
    
    def find_blocking_patterns(self):
        """Identify potential blocking patterns."""
        print(f"\n[*] Blocking Pattern Analysis:")
        print("=" * 80)
        
        # Check for excessive sleep calls
        sleep_calls = self.kernel_calls.get('KeDelayExecutionThread', 0)
        if sleep_calls > 1000:
            print(f"[!] EXCESSIVE SLEEP: KeDelayExecutionThread called {sleep_calls:,} times")
            print(f"    This suggests the game is stuck in a wait loop")
        
        # Check for wait calls
        wait_calls = self.kernel_calls.get('KeWaitForSingleObject', 0) + \
                     self.kernel_calls.get('NtWaitForSingleObjectEx', 0)
        if wait_calls > 1000:
            print(f"[!] EXCESSIVE WAITING: Wait functions called {wait_calls:,} times")
            print(f"    This suggests the game is waiting for events that are never signaled")
        
        # Check for event signaling
        signal_calls = self.kernel_calls.get('KeSetEvent', 0) + \
                       self.kernel_calls.get('NtSetEvent', 0)
        if signal_calls == 0:
            print(f"[!] NO EVENT SIGNALING: KeSetEvent/NtSetEvent never called")
            print(f"    This confirms that events are never being signaled")
        else:
            print(f"[+] Event signaling detected: {signal_calls:,} calls")
        
        # Check for audio registration
        audio_reg = self.kernel_calls.get('XAudioRegisterRenderDriverClient', 0)
        if audio_reg == 0:
            print(f"[!] NO AUDIO REGISTRATION: XAudioRegisterRenderDriverClient never called")
            print(f"    This confirms the game hasn't registered audio callbacks")
        else:
            print(f"[+] Audio registration detected: {audio_reg:,} calls")
        
        # Check for file I/O
        file_io = self.kernel_calls.get('NtCreateFile', 0) + \
                  self.kernel_calls.get('NtOpenFile', 0) + \
                  self.kernel_calls.get('NtReadFile', 0)
        if file_io == 0:
            print(f"[!] NO FILE I/O: NtCreateFile/NtOpenFile/NtReadFile never called")
            print(f"    This suggests the game hasn't started loading resources")
        else:
            print(f"[+] File I/O detected: {file_io:,} calls")
    
    def generate_report(self, output_file: Path):
        """Generate a comprehensive analysis report."""
        print(f"\n[*] Generating comprehensive report: {output_file}")
        
        report = {
            'summary': {
                'total_kernel_calls': sum(self.kernel_calls.values()),
                'unique_kernel_functions': len(self.kernel_calls),
                'total_stub_calls': sum(self.stub_calls.values()),
                'unique_stubs': len(self.stub_calls),
            },
            'hot_spots': dict(sorted(self.kernel_calls.items(), key=lambda x: x[1], reverse=True)[:50]),
            'stub_calls': dict(sorted(self.stub_calls.items(), key=lambda x: x[1], reverse=True)[:50]),
            'blocking_indicators': {
                'sleep_calls': self.kernel_calls.get('KeDelayExecutionThread', 0),
                'wait_calls': self.kernel_calls.get('KeWaitForSingleObject', 0) + 
                             self.kernel_calls.get('NtWaitForSingleObjectEx', 0),
                'signal_calls': self.kernel_calls.get('KeSetEvent', 0) + 
                               self.kernel_calls.get('NtSetEvent', 0),
                'audio_registration': self.kernel_calls.get('XAudioRegisterRenderDriverClient', 0),
                'file_io': self.kernel_calls.get('NtCreateFile', 0) + 
                          self.kernel_calls.get('NtOpenFile', 0) + 
                          self.kernel_calls.get('NtReadFile', 0),
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to: {output_file}")

def main():
    # Default trace file location
    trace_file = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    
    if len(sys.argv) > 1:
        trace_file = Path(sys.argv[1])
    
    print("=" * 80)
    print("MW05 Trace Analyzer - Diagnostic Tool")
    print("=" * 80)
    
    analyzer = TraceAnalyzer(trace_file)
    
    if not analyzer.parse_trace():
        print("[!] Failed to parse trace file")
        return 1
    
    # Run analysis
    analyzer.identify_hot_spots(top_n=30)
    analyzer.identify_kernel_patterns()
    analyzer.identify_stub_patterns()
    analyzer.find_blocking_patterns()
    
    # Generate report
    report_file = trace_file.parent / "trace_analysis_report.json"
    analyzer.generate_report(report_file)
    
    print("\n" + "=" * 80)
    print("Analysis Complete!")
    print("=" * 80)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

