#!/usr/bin/env python3
"""
Efficient Xenia log analyzer to understand game initialization sequence.
Helps identify what happens between import table processing and first file I/O.
"""

import re
import sys
from collections import defaultdict, Counter
from pathlib import Path

class XeniaLogAnalyzer:
    def __init__(self, log_path):
        self.log_path = Path(log_path)
        self.lines = []
        self.import_table_line = -1
        self.first_file_io_line = -1
        self.thread_creations = []
        self.kernel_calls = defaultdict(list)
        
    def load_log(self):
        """Load log file into memory."""
        print(f"Loading {self.log_path}...")
        with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.lines = f.readlines()
        print(f"Loaded {len(self.lines)} lines")
        
    def find_key_events(self):
        """Find key events in the log."""
        print("\nFinding key events...")
        
        for i, line in enumerate(self.lines):
            # Find import table processing
            if 'Imports:' in line or 'import table' in line.lower():
                if self.import_table_line == -1:
                    self.import_table_line = i
                    print(f"  Import table processing at line {i}")
            
            # Find first file I/O (actual call, not import table entry)
            if self.first_file_io_line == -1:
                # Skip import table entries (lines starting with F or V)
                if re.search(r'NtCreateFile|NtOpenFile|NtReadFile', line) and not re.match(r'^\s+[FV]\s', line):
                    self.first_file_io_line = i
                    print(f"  First file I/O at line {i}: {line.strip()[:80]}")
            
            # Find thread creations
            if re.search(r'ExCreateThread|CreateThread|thread.*created', line, re.IGNORECASE):
                self.thread_creations.append((i, line.strip()))
        
        print(f"  Found {len(self.thread_creations)} thread creations")
        
    def analyze_initialization_sequence(self):
        """Analyze what happens between import table and first file I/O."""
        if self.import_table_line == -1:
            print("\nWARNING: Import table processing not found!")
            return
        
        if self.first_file_io_line == -1:
            print("\nWARNING: No file I/O found in log!")
            end_line = min(self.import_table_line + 10000, len(self.lines))
        else:
            end_line = self.first_file_io_line
        
        print(f"\nAnalyzing initialization sequence (lines {self.import_table_line} to {end_line})...")
        
        # Extract kernel function calls
        kernel_pattern = re.compile(r'(Nt\w+|Ke\w+|Ex\w+|Rtl\w+|Xam\w+|Vd\w+)\s*\(')
        
        for i in range(self.import_table_line, end_line):
            line = self.lines[i]
            matches = kernel_pattern.findall(line)
            for func in matches:
                self.kernel_calls[func].append(i)
        
        # Print top kernel calls
        print("\nTop 30 kernel functions called during initialization:")
        sorted_calls = sorted(self.kernel_calls.items(), key=lambda x: len(x[1]), reverse=True)
        for func, lines in sorted_calls[:30]:
            print(f"  {func:40s} {len(lines):5d} calls")
    
    def find_thread_creation_sequence(self):
        """Analyze thread creation sequence."""
        if not self.thread_creations:
            print("\nNo thread creations found!")
            return
        
        print(f"\nThread creation sequence ({len(self.thread_creations)} threads):")
        for i, (line_num, line) in enumerate(self.thread_creations[:20]):
            # Extract entry point if present
            entry_match = re.search(r'entry[:\s=]+([0-9A-Fa-fx]+)', line)
            entry = entry_match.group(1) if entry_match else "unknown"
            print(f"  {i+1:2d}. Line {line_num:6d}: entry={entry:12s}")
            if i < 5:  # Show full line for first 5
                print(f"      {line[:120]}")
    
    def find_flag_operations(self):
        """Find operations on the unblock flag (0x82A2CF40)."""
        print("\nSearching for flag operations (0x82A2CF40)...")
        flag_ops = []
        
        for i, line in enumerate(self.lines):
            if '82A2CF40' in line or '0x82A2CF40' in line:
                flag_ops.append((i, line.strip()))
        
        if flag_ops:
            print(f"Found {len(flag_ops)} operations on flag 0x82A2CF40:")
            for i, (line_num, line) in enumerate(flag_ops[:20]):
                print(f"  {i+1:2d}. Line {line_num:6d}: {line[:100]}")
        else:
            print("  No operations found on flag 0x82A2CF40")
    
    def find_sub_82442080_calls(self):
        """Find calls to sub_82442080 (the function that sets the unblock flag)."""
        print("\nSearching for sub_82442080 calls...")
        calls = []

        for i, line in enumerate(self.lines):
            if '82442080' in line:
                calls.append((i, line.strip()))

        if calls:
            print(f"Found {len(calls)} references to sub_82442080:")
            for i, (line_num, line) in enumerate(calls[:20]):
                print(f"  {i+1:2d}. Line {line_num:6d}: {line[:100]}")
        else:
            print("  No references to sub_82442080 found")

    def analyze_sleep_loop(self):
        """Analyze the sleep loop pattern."""
        print("\nAnalyzing sleep loop (KeDelayExecutionThread at lr=0x8262F300)...")

        sleep_lines = []
        for i, line in enumerate(self.lines):
            if 'KeDelayExecutionThread' in line and 'lr=0x8262F300' in line:
                sleep_lines.append(i)

        if not sleep_lines:
            print("  No sleep loop found")
            return

        print(f"  Found {len(sleep_lines)} sleep calls at lr=0x8262F300")
        print(f"  First sleep at line {sleep_lines[0]}")
        print(f"  Last sleep at line {sleep_lines[-1]}")

        # Find what happens after the last sleep
        print(f"\n  Lines after last sleep (showing next 30 non-sleep lines):")
        count = 0
        for i in range(sleep_lines[-1] + 1, min(sleep_lines[-1] + 500, len(self.lines))):
            if 'KeDelayExecutionThread' not in self.lines[i]:
                print(f"    {i:6d}: {self.lines[i].strip()[:100]}")
                count += 1
                if count >= 30:
                    break
    
    def compare_with_our_trace(self, our_trace_path):
        """Compare Xenia's sequence with our trace."""
        print(f"\nComparing with our trace: {our_trace_path}")
        
        if not Path(our_trace_path).exists():
            print(f"  WARNING: {our_trace_path} not found!")
            return
        
        # Load our trace
        with open(our_trace_path, 'r', encoding='utf-8', errors='ignore') as f:
            our_lines = f.readlines()
        
        # Find thread creations in our trace
        our_threads = []
        for i, line in enumerate(our_lines):
            if 'ExCreateThread' in line and 'entry=' in line:
                entry_match = re.search(r'entry=([0-9A-Fa-f]+)', line)
                if entry_match:
                    our_threads.append(entry_match.group(1))
        
        print(f"\nOur implementation created {len(our_threads)} threads:")
        for i, entry in enumerate(our_threads[:10]):
            print(f"  {i+1:2d}. Entry: 0x{entry}")
        
        # Compare with Xenia
        xenia_entries = set()
        for _, line in self.thread_creations:
            entry_match = re.search(r'entry[:\s=]+([0-9A-Fa-fx]+)', line)
            if entry_match:
                entry = entry_match.group(1).replace('0x', '').upper()
                xenia_entries.add(entry)
        
        our_entries = set(e.upper() for e in our_threads)
        
        print(f"\nXenia created {len(xenia_entries)} unique threads")
        print(f"We created {len(our_entries)} unique threads")
        
        missing = xenia_entries - our_entries
        if missing:
            print(f"\nThreads in Xenia but not in our implementation ({len(missing)}):")
            for entry in sorted(missing)[:10]:
                print(f"  0x{entry}")
    
    def export_initialization_sequence(self, output_path):
        """Export the initialization sequence to a file."""
        if self.import_table_line == -1:
            print("\nCannot export: import table not found")
            return
        
        end_line = self.first_file_io_line if self.first_file_io_line != -1 else min(self.import_table_line + 5000, len(self.lines))
        
        output = Path(output_path)
        print(f"\nExporting initialization sequence to {output}...")
        
        with open(output, 'w', encoding='utf-8') as f:
            f.write(f"Xenia Initialization Sequence\n")
            f.write(f"Lines {self.import_table_line} to {end_line}\n")
            f.write("=" * 80 + "\n\n")
            
            for i in range(self.import_table_line, end_line):
                f.write(f"{i:6d}: {self.lines[i]}")
        
        print(f"  Exported {end_line - self.import_table_line} lines")

def main():
    log_path = Path("tools/xenia.log")
    
    if not log_path.exists():
        print(f"ERROR: {log_path} not found!")
        print("Please ensure tools/xenia.log exists")
        sys.exit(1)
    
    analyzer = XeniaLogAnalyzer(log_path)
    analyzer.load_log()
    analyzer.find_key_events()
    analyzer.analyze_initialization_sequence()
    analyzer.find_thread_creation_sequence()
    analyzer.find_flag_operations()
    analyzer.find_sub_82442080_calls()
    analyzer.analyze_sleep_loop()

    # Compare with our trace if it exists
    our_trace = Path("out/build/x64-Clang-Debug/Mw05Recomp/mw05_host_trace.log")
    if our_trace.exists():
        analyzer.compare_with_our_trace(our_trace)
    
    # Export initialization sequence
    analyzer.export_initialization_sequence("tools/xenia_init_sequence.txt")
    
    print("\n" + "=" * 80)
    print("Analysis complete!")
    print("=" * 80)

if __name__ == "__main__":
    main()

