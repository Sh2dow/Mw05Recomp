# MW05 Minimal TOML Approach - 2025-10-29

## Problem Statement

MW05 recompilation was using a massive function list in `MW05.toml`:
- **24,088 functions** explicitly declared
- **9.87 MB** of function definitions
- Covers **7.90 MB** of code space

This contrasts sharply with UnleashedRecomp (Sonic Unleashed):
- **Only 43 functions** declared
- Only functions with problematic jump tables that the recompiler can't analyze

## Root Cause Analysis

The original function extraction scripts (`Auto_Function_Parser.py` and `Auto_Function_Parser_v2.py`) were designed to extract **ALL** functions from the IDA HTML export, not just the problematic ones.

This massive function list may be causing:
1. **Slow compilation times** - Recompiler has to process 24K+ function declarations
2. **Initialization delays** - Game may be stuck initializing all these functions
3. **Potential stability issues** - Conflicts between declared and auto-discovered functions

## UnleashedRecomp's Approach

UnleashedRecomp follows a **minimal declaration** philosophy:

```toml
# Only declare functions that CANNOT be analyzed automatically
functions = [
    { address = 0x824E7EF0, size = 0x98 },   # Has jump table
    { address = 0x824E7F28, size = 0x60 },   # Has jump table
    # ... only 43 total
]
```

**Key insight**: The XenonRecomp recompiler can automatically discover and analyze most functions from the XEX's `.pdata` section. We only need to declare functions that:
- Have complex jump tables the recompiler can't analyze
- Don't exist in `.pdata`
- Have other analysis issues

## Solution: Minimal TOML

### Created Tools

1. **`tools/Create_Minimal_TOML.py`**
   - Creates a minimal MW05.toml with 0 functions
   - Includes only essential prolog/epilog helper addresses
   - Uses aggressive register optimization (like UnleashedRecomp)

2. **`tools/Extract_Minimal_Functions.py`**
   - Extracts only problematic functions from recompiler error logs
   - Filters by size, alignment, address range
   - Produces minimal function list

3. **`tools/Analyze_Function_List.py`**
   - Analyzes function statistics in TOML files
   - Compares different TOML configurations
   - Provides recommendations

### Migration Process

```bash
# 1. Backup current TOML (DONE)
python tools/Create_Minimal_TOML.py --backup
# Creates: Mw05RecompLib/config/MW05_full.toml (backup)
# Creates: Mw05RecompLib/config/MW05_minimal.toml (0 functions)

# 2. Apply minimal TOML
python tools/Create_Minimal_TOML.py --apply

# 3. Rebuild and test
.\build_cmd.ps1 -Stage app

# 4. Check for recompiler errors
# If errors occur, extract problematic functions:
python tools/Extract_Minimal_Functions.py <build_log> MW05_functions.toml

# 5. Add problematic functions to MW05.toml
# Manually merge MW05_functions.toml into MW05.toml
```

## Expected Results

### Best Case
- Recompiler handles all functions automatically
- **0 functions** need to be declared
- Faster compilation
- Faster initialization
- Game starts rendering immediately

### Likely Case
- Recompiler finds a few problematic functions (like UnleashedRecomp's 43)
- We add only those to MW05.toml
- Still **99%+ reduction** in declared functions (24,088 → ~50)

### Worst Case
- Recompiler needs many functions declared
- We incrementally add them using `Extract_Minimal_Functions.py`
- Still better than declaring all 24K+ upfront

## Register Optimization Settings

The minimal TOML uses aggressive register optimization (matching UnleashedRecomp):

```toml
skip_lr = true                    # Skip link register tracking
skip_msr = true                   # Skip machine state register
ctr_as_local = true              # Treat counter register as local
xer_as_local = true              # Treat XER as local
reserved_as_local = true         # Treat reserved register as local
cr_as_local = true               # Treat condition register as local
non_argument_as_local = true     # Non-argument registers as local
non_volatile_as_local = true     # Non-volatile registers as local
```

These settings tell the recompiler to make more aggressive assumptions about register usage, resulting in more efficient code generation.

## Files Created

- `Mw05RecompLib/config/MW05_full.toml` - Backup of original (24,088 functions)
- `Mw05RecompLib/config/MW05_minimal.toml` - Minimal version (0 functions)
- `tools/Create_Minimal_TOML.py` - TOML generator
- `tools/Extract_Minimal_Functions.py` - Error-based function extractor
- `tools/Analyze_Function_List.py` - TOML analyzer

## Next Steps

1. **Apply minimal TOML**: `python tools/Create_Minimal_TOML.py --apply`
2. **Rebuild**: `.\build_cmd.ps1 -Stage app`
3. **Test**: `python scripts/auto_handle_messageboxes.py --duration 30`
4. **Monitor**: Check build output for recompiler errors
5. **Iterate**: Add only problematic functions if needed

## References

- UnleashedRecomp SWA.toml: 43 functions (switch tables only)
- MW05 original: 24,088 functions (everything)
- Target: ~50 functions (estimated based on UnleashedRecomp)

## Hypothesis

The stuck initialization issue may be caused by the massive function list. By reducing to a minimal set, we expect:
- Faster startup
- Reduced memory usage
- Potential fix for initialization hang
- Better alignment with UnleashedRecomp's proven approach

