#!/usr/bin/env python3
"""Find cross-references to a function in IDA HTML export."""

import re
import sys

def find_xrefs(html_file, target_addr):
    """Find all references to a target address in IDA HTML."""
    
    print(f"Searching for references to {target_addr}...")
    
    with open(html_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Search for the target address in the HTML
    # IDA HTML format: addresses are in hex without 0x prefix
    pattern = rf'\b{target_addr}\b'
    
    matches = []
    for match in re.finditer(pattern, content, re.IGNORECASE):
        # Get context around the match (500 chars before and after)
        start = max(0, match.start() - 500)
        end = min(len(content), match.end() + 500)
        context = content[start:end]
        matches.append((match.start(), context))
    
    print(f"Found {len(matches)} references to {target_addr}")
    
    # Save to file
    output_file = f'IDA_dumps/{target_addr}_xrefs.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"Cross-references to {target_addr}\n")
        f.write("=" * 80 + "\n\n")
        
        for i, (pos, context) in enumerate(matches[:50]):  # Limit to first 50
            f.write(f"Reference #{i+1} at position {pos}:\n")
            f.write("-" * 80 + "\n")
            f.write(context)
            f.write("\n" + "=" * 80 + "\n\n")
    
    print(f"Saved to {output_file}")
    
    # Also print first few matches
    print("\nFirst 5 references:")
    for i, (pos, context) in enumerate(matches[:5]):
        print(f"\n--- Reference #{i+1} ---")
        # Extract just the line containing the address
        lines = context.split('\n')
        for line in lines:
            if target_addr.lower() in line.lower():
                print(line.strip())
                break

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python find_xrefs.py <address>")
        print("Example: python find_xrefs.py 826E87E0")
        sys.exit(1)
    
    target = sys.argv[1].upper()
    find_xrefs('NfsMWEurope.xex.html', target)

