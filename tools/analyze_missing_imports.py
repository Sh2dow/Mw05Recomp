#!/usr/bin/env python3
"""
Analyze missing imports from stderr log
"""

import re
import sys
from pathlib import Path
from collections import Counter

def analyze_missing_imports(log_path):
    """Extract and analyze missing imports"""
    
    if not log_path.exists():
        print(f"Error: {log_path} not found", file=sys.stderr)
        return 1
    
    missing_imports = []
    
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if 'NOT IMPLEMENTED' in line:
                # Extract function name from: __imp__FunctionName (ordinal=...)
                match = re.search(r'__imp__([A-Za-z0-9_]+)', line)
                if match:
                    missing_imports.append(match.group(1))
    
    # Count occurrences
    import_counts = Counter(missing_imports)
    
    print(f"Total missing import calls: {len(missing_imports)}")
    print(f"Unique missing imports: {len(import_counts)}")
    print()
    
    # Group by prefix
    prefixes = {}
    for imp in import_counts.keys():
        # Extract prefix (e.g., "Xam", "Vd", "Ke", etc.)
        if imp.startswith('Xam'):
            prefix = 'Xam'
        elif imp.startswith('Vd'):
            prefix = 'Vd'
        elif imp.startswith('Ke'):
            prefix = 'Ke'
        elif imp.startswith('Nt'):
            prefix = 'Nt'
        elif imp.startswith('Rtl'):
            prefix = 'Rtl'
        elif imp.startswith('Ex'):
            prefix = 'Ex'
        elif imp.startswith('Ob'):
            prefix = 'Ob'
        elif imp.startswith('Io'):
            prefix = 'Io'
        elif imp.startswith('Mm'):
            prefix = 'Mm'
        elif imp.startswith('Ps'):
            prefix = 'Ps'
        elif imp.startswith('Hal'):
            prefix = 'Hal'
        elif imp.startswith('XeCrypt'):
            prefix = 'XeCrypt'
        elif imp.startswith('NetDll'):
            prefix = 'NetDll'
        elif imp.startswith('XGet'):
            prefix = 'XGet'
        elif imp.startswith('XMsg'):
            prefix = 'XMsg'
        elif imp.startswith('XNotify'):
            prefix = 'XNotify'
        else:
            prefix = 'Other'
        
        if prefix not in prefixes:
            prefixes[prefix] = []
        prefixes[prefix].append(imp)
    
    print("Missing imports by category:")
    print("=" * 60)
    for prefix in sorted(prefixes.keys(), key=lambda x: len(prefixes[x]), reverse=True):
        imports = sorted(set(prefixes[prefix]))
        print(f"\n{prefix}* functions ({len(imports)} unique):")
        for imp in imports[:20]:  # Show first 20
            count = import_counts[imp]
            print(f"  {imp} (called {count} times)")
        if len(imports) > 20:
            print(f"  ... and {len(imports) - 20} more")
    
    return 0

def main():
    repo_root = Path(__file__).parent.parent
    log_path = repo_root / "very_long_run_stderr.txt"
    
    return analyze_missing_imports(log_path)

if __name__ == "__main__":
    sys.exit(main())

