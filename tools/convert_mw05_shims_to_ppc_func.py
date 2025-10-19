#!/usr/bin/env python3
"""
Convert MW05Shim_sub_* functions to PPC_FUNC_IMPL pattern.

This script converts all MW05Shim_sub_XXXXXXXX functions to use the proper
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX) + PPC_FUNC(sub_XXXXXXXX) pattern.
"""

import re
import sys
from pathlib import Path

def convert_shim_to_ppc_func(content: str) -> str:
    """Convert MW05Shim_sub_* functions to PPC_FUNC_IMPL pattern."""
    
    # Pattern to match MW05Shim_sub_XXXXXXXX function definitions
    # Matches: void MW05Shim_sub_XXXXXXXX(PPCContext& ctx, uint8_t* base) {
    pattern = r'void MW05Shim_(sub_[0-9A-F]{8})\(PPCContext& ctx, uint8_t\* base\) \{'
    
    def replace_function(match):
        func_name = match.group(1)  # e.g., "sub_82596978"
        
        # Create the replacement
        replacement = f'''// Convert MW05Shim_{func_name} to PPC_FUNC_IMPL pattern
PPC_FUNC_IMPL(__imp__{func_name});
PPC_FUNC({func_name}) {{'''
        
        return replacement
    
    # Replace all function definitions
    result = re.sub(pattern, replace_function, content)
    
    # Now we need to add SetPPCContext(ctx); before each __imp__sub_* call
    # Pattern to match: __imp__sub_XXXXXXXX(ctx, base);
    imp_pattern = r'(\s+)(__imp__sub_[0-9A-F]{8}\(ctx, base\);)'
    
    def add_set_context(match):
        indent = match.group(1)
        call = match.group(2)
        return f'{indent}SetPPCContext(ctx);\n{indent}{call}'
    
    result = re.sub(imp_pattern, add_set_context, result)
    
    return result

def main():
    if len(sys.argv) != 2:
        print("Usage: python convert_mw05_shims_to_ppc_func.py <file_path>")
        sys.exit(1)
    
    file_path = Path(sys.argv[1])
    
    if not file_path.exists():
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    
    # Read the file
    content = file_path.read_text(encoding='utf-8')
    
    # Convert the content
    converted = convert_shim_to_ppc_func(content)
    
    # Write back
    file_path.write_text(converted, encoding='utf-8')
    
    print(f"Successfully converted {file_path}")

if __name__ == '__main__':
    main()

