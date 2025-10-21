# Logging & Traces

## Where Logs Live
- `out/build/x64-Clang-Debug/Mw05Recomp/`
  - `test_*.txt` - Test run outputs
  - `debug_*.txt` - Debug session outputs
  - `codegen_*.txt` - Code generation logs
  - `baseline_*.txt` - Baseline test outputs
  - `mw05_host_trace.log` - Runtime trace of all kernel calls
- `ida_logs/` - IDA HTTP outputs (decompile/disasm/bytes JSON)
- `traces/` - Organized traces/logs/dumps for debugging

## Why Here?
- Keeps repo root clean
- Co-located with binaries
- .gitignored (no accidental commits)
- Easy cleanup

## Common Actions

### Run with Debug Logging
```powershell
./run_with_debug.ps1
# Logs to out/build/x64-Clang-Debug/Mw05Recomp/debug_stderr.txt
```

### List Newest Test Logs
```powershell
Get-ChildItem out/build/x64-Clang-Debug/Mw05Recomp/test_*.txt | Sort-Object LastWriteTime -Descending
```

### IDA HTTP Examples
```powershell
# Get decompiled C code for a function
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/decompile?ea=0x8211E470').Content | ConvertFrom-Json | Select-Object -ExpandProperty pseudocode

# Get 50 assembly instructions starting at address
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x8211E470&count=50').Content | ConvertFrom-Json | Select-Object -ExpandProperty disasm

# Get 64 bytes of raw data
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/bytes?ea=0x82065268&count=64').Content | ConvertFrom-Json | Select-Object -ExpandProperty bytes_hex
```

## Cleanup
```powershell
# Remove all test logs
Remove-Item out/build/x64-Clang-Debug/Mw05Recomp/*.txt

# Remove IDA logs
Remove-Item ida_logs/*.json

# Remove traces
Remove-Item traces/*.txt
```

## Verbosity Control

### Environment Variables
```powershell
$env:MW05_DEBUG_GRAPHICS = "0|1|2|3"  # 0=off, 1=minimal, 2=normal, 3=verbose
$env:MW05_DEBUG_PM4 = "0|1|2|3"
$env:MW05_DEBUG_KERNEL = "0|1|2|3"
$env:MW05_DEBUG_THREAD = "0|1|2|3"
$env:MW05_DEBUG_HEAP = "0|1|2|3"
$env:MW05_DEBUG_FILEIO = "0|1|2|3"
```

### Performance Impact
- **Before verbosity control**: 3.5 MB logs in 30 seconds, 3,416 "No changes detected" messages
- **After verbosity control**: 293 KB logs in 30 seconds (92% reduction!), 0 spam messages

## Best Practices
- Use the log dirs; don't commit logs
- Use descriptive names for test runs
- Clean periodically to avoid disk space issues
- Use verbosity control to reduce log spam
- Enable verbose logging only when debugging specific issues

