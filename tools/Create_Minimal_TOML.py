#!/usr/bin/env python3
"""
Create_Minimal_TOML.py - Create a minimal MW05.toml following UnleashedRecomp's approach

This script creates a minimal TOML configuration with only the essential helper functions
and prolog/epilog addresses, letting the recompiler handle everything else automatically.

Usage:
    python Create_Minimal_TOML.py [--output <path>] [--backup]

Options:
    --output <path>  Output path (default: Mw05RecompLib/config/MW05_minimal.toml)
    --backup         Backup existing MW05.toml to MW05_full.toml
    --apply          Apply the minimal TOML (replace MW05.toml)

Example:
    python Create_Minimal_TOML.py --backup
    python Create_Minimal_TOML.py --backup --apply
"""

import sys
import shutil
from pathlib import Path
from datetime import datetime

MINIMAL_TOML_TEMPLATE = """## Need for Speed: Most Wanted (2005) – Xbox 360
## XenonRecomp title profile (config) for static recompilation
## MINIMAL VERSION - Following UnleashedRecomp's approach

[main]
# XEX input/output paths are relative to this config file location
file_path = "../private/default.xex"
# Optional patch file (.xexp) if present
# patch_file_path = "../private/default.xexp"
patched_file_path = "../private/default_patched.xex"
out_directory_path = "../ppc"
switch_table_file_path = "MW05_switch_tables.toml"

# Register allocation heuristics
# Following UnleashedRecomp's aggressive optimization settings
skip_lr = true
skip_msr = true
ctr_as_local = true
xer_as_local = true
reserved_as_local = true
cr_as_local = true
non_argument_as_local = true
non_volatile_as_local = true

# Prolog/epilog helpers (MW'05 addresses)
restgprlr_14_address = 0x826BDD80
savegprlr_14_address = 0x826BDD30
restfpr_14_address   = 0x826BED3C
savefpr_14_address   = 0x826BECF0
restvmx_14_address   = 0x826BEA58
savevmx_14_address   = 0x826BE7C0
restvmx_64_address   = 0x826BEAEC
savevmx_64_address   = 0x826BE854

# longjmp_address = 0x00000000
# setjmp_address = 0x00000000

# These functions do not exist in .pdata and do
# not analyze properly due to having jump tables
# NOTE: This list should be populated from actual recompiler errors
# Currently empty - let the recompiler handle everything automatically
functions = [
]

# Invalid instructions (if any are discovered during testing)
# invalid_instructions = [
#     { data = 0x00000000, size = 4 }, # Padding
# ]

# Mid-ASM hooks (if needed for game-specific fixes)
# [[midasm_hook]]
# name = "ExampleMidAsmHook"
# address = 0x82000000
# registers = ["r3"]
"""

def parse_args():
    """Parse command line arguments"""
    config = {
        'output': 'Mw05RecompLib/config/MW05_minimal.toml',
        'backup': False,
        'apply': False
    }
    
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == '--output' and i + 1 < len(sys.argv):
            config['output'] = sys.argv[i + 1]
            i += 2
        elif arg == '--backup':
            config['backup'] = True
            i += 1
        elif arg == '--apply':
            config['apply'] = True
            i += 1
        elif arg in ['-h', '--help']:
            print(__doc__)
            sys.exit(0)
        else:
            i += 1
    
    return config

def backup_existing_toml():
    """Backup existing MW05.toml"""
    original = Path('Mw05RecompLib/config/MW05.toml')
    backup = Path('Mw05RecompLib/config/MW05_full.toml')
    
    if not original.exists():
        print(f"[!] Warning: {original} does not exist")
        return False
    
    if backup.exists():
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup = Path(f'Mw05RecompLib/config/MW05_full_{timestamp}.toml')
    
    print(f"[*] Backing up {original} -> {backup}")
    shutil.copy2(original, backup)
    print(f"[+] Backup created: {backup}")
    return True

def create_minimal_toml(output_path):
    """Create minimal TOML file"""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    
    print(f"[*] Creating minimal TOML: {output}")
    
    with open(output, 'w', encoding='utf-8') as f:
        f.write(MINIMAL_TOML_TEMPLATE)
    
    print(f"[+] Created: {output}")
    return True

def apply_minimal_toml(minimal_path):
    """Apply minimal TOML by replacing MW05.toml"""
    minimal = Path(minimal_path)
    target = Path('Mw05RecompLib/config/MW05.toml')
    
    if not minimal.exists():
        print(f"[!] Error: {minimal} does not exist")
        return False
    
    print(f"[*] Applying minimal TOML: {minimal} -> {target}")
    shutil.copy2(minimal, target)
    print(f"[+] Applied: {target}")
    return True

def main():
    config = parse_args()
    
    print("=" * 70)
    print("MW05 Minimal TOML Creator")
    print("Following UnleashedRecomp's approach")
    print("=" * 70)
    print()
    
    # Backup if requested
    if config['backup']:
        backup_existing_toml()
        print()
    
    # Create minimal TOML
    create_minimal_toml(config['output'])
    print()
    
    # Apply if requested
    if config['apply']:
        apply_minimal_toml(config['output'])
        print()
    
    # Summary
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print()
    print(f"Minimal TOML created: {config['output']}")
    
    if config['backup']:
        print("Original MW05.toml backed up to MW05_full.toml")
    
    if config['apply']:
        print("Minimal TOML applied to MW05.toml")
        print()
        print("Next steps:")
        print("  1. Rebuild: .\\build_cmd.ps1 -Stage app")
        print("  2. Test: python scripts/auto_handle_messageboxes.py --duration 30")
        print("  3. Check for recompiler errors in build output")
        print("  4. If errors occur, add problematic functions to MW05.toml")
    else:
        print()
        print("To apply this minimal TOML:")
        print(f"  python {sys.argv[0]} --backup --apply")
        print()
        print("Or manually:")
        print(f"  copy {config['output']} Mw05RecompLib/config/MW05.toml")
        print("  .\\build_cmd.ps1 -Stage app")
    
    print()
    print("=" * 70)

if __name__ == '__main__':
    main()

