#!/usr/bin/env python3
"""Analyze the structure of sub_82441CF0 to find conditional logic."""

import re

def find_function_bounds(filename, func_name):
    """Find the start and end lines of a function."""
    with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    start_line = None
    end_line = None
    
    for i, line in enumerate(lines):
        # Find function start
        if f'__imp__{func_name}' in line and 'PPC_FUNC_IMPL' in line:
            start_line = i
        
        # Find function end (next function or return)
        if start_line is not None and i > start_line:
            if 'PPC_FUNC_IMPL' in line or '__attribute__((alias' in line:
                end_line = i - 1
                break
    
    return start_line, end_line, lines

def analyze_function_structure(lines, start, end):
    """Analyze the structure of the function."""
    
    print(f"Function spans lines {start} to {end} ({end - start} lines)")
    print()
    
    # Find all function calls
    calls = []
    for i in range(start, end + 1):
        line = lines[i]
        # Match function calls like "sub_XXXXXXXX(ctx, base);"
        match = re.search(r'(sub_[0-9A-F]+)\(ctx, base\)', line)
        if match:
            func = match.group(1)
            # Get the lr value from previous line
            lr = None
            if i > 0 and 'ctx.lr = ' in lines[i-1]:
                lr_match = re.search(r'ctx\.lr = (0x[0-9A-F]+)', lines[i-1])
                if lr_match:
                    lr = lr_match.group(1)
            calls.append((i, func, lr))
    
    print(f"Found {len(calls)} function calls:")
    for line_num, func, lr in calls[:30]:  # Show first 30
        print(f"  Line {line_num:6d}: {func:20s} lr={lr}")
    
    if len(calls) > 30:
        print(f"  ... and {len(calls) - 30} more")
    print()
    
    # Find conditional branches
    branches = []
    for i in range(start, end + 1):
        line = lines[i]
        if 'if (ctx.cr' in line and 'goto' in line:
            # Extract the condition and target
            match = re.search(r'if \(ctx\.(cr[0-9]+\.[a-z]+)\) goto (loc_[0-9A-F]+)', line)
            if match:
                cond = match.group(1)
                target = match.group(2)
                branches.append((i, cond, target))
    
    print(f"Found {len(branches)} conditional branches:")
    for line_num, cond, target in branches[:20]:  # Show first 20
        print(f"  Line {line_num:6d}: if ({cond}) goto {target}")
    
    if len(branches) > 20:
        print(f"  ... and {len(branches) - 20} more")
    print()
    
    # Find labels (goto targets)
    labels = []
    for i in range(start, end + 1):
        line = lines[i]
        if re.match(r'\s*loc_[0-9A-F]+:', line):
            match = re.search(r'(loc_[0-9A-F]+):', line)
            if match:
                labels.append((i, match.group(1)))
    
    print(f"Found {len(labels)} labels:")
    for line_num, label in labels[:20]:  # Show first 20
        print(f"  Line {line_num:6d}: {label}")
    
    if len(labels) > 20:
        print(f"  ... and {len(labels) - 20} more")
    print()
    
    return calls, branches, labels

if __name__ == '__main__':
    filename = 'Mw05RecompLib/ppc/ppc_recomp.54.cpp'
    func_name = 'sub_82441CF0'
    
    print(f"Analyzing {func_name}...")
    print()
    
    start, end, lines = find_function_bounds(filename, func_name)
    
    if start is None:
        print(f"Function {func_name} not found!")
    else:
        calls, branches, labels = analyze_function_structure(lines, start, end)
        
        # Find the call to sub_8262DE60
        print("\nLooking for sub_8262DE60 call:")
        for line_num, func, lr in calls:
            if func == 'sub_8262DE60':
                print(f"  Found at line {line_num} with lr={lr}")
                
                # Show context around this call
                print(f"\n  Context (10 lines before and after):")
                for i in range(max(start, line_num - 10), min(end, line_num + 10)):
                    marker = ">>>" if i == line_num else "   "
                    print(f"  {marker} {i:6d}: {lines[i]}", end='')

