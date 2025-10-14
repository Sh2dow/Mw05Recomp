# Logging and Debug Output Locations

This document describes where debug logs and trace files are stored in the Mw05Recomp project.

## 📁 Log Directory Structure

### Application Build Logs
**Location**: `out/build/x64-Clang-Debug/Mw05Recomp/`

All runtime debug logs and trace files from the application are stored here:

- `test_*.txt` - Test run outputs and traces
- `debug_*.txt` - Debug stderr captures
- `codegen_*.txt` - Code generation debug outputs
- `baseline_*.txt` - Baseline test outputs

**Why here?**
- Keeps the repository root clean
- Co-located with the built executable
- Automatically cleaned when build directory is deleted
- Not committed to git (covered by `.gitignore` pattern `[Oo]ut/`)

### IDA Pro Decompilation Logs
**Location**: `ida_logs/`

JSON files with decompiled functions and disassembly from IDA Pro:

- `sub_<address>_decompile.json` - Hex-Rays pseudocode (C-like decompilation)
- `sub_<address>_disasm.json` - Raw assembly instructions
- `sub_<address>_full.json` - Complete function information

**Why here?**
- Centralized location for all IDA outputs
- Easy to find and reference during debugging
- Excluded from git via `.gitignore`
- Separate from build artifacts

## 🔧 Scripts That Generate Logs

### PowerShell Scripts

#### `run_with_debug.ps1`
Writes to: `$LogDir\debug_stderr.txt` (where `$LogDir = ".\out\build\x64-Clang-Debug\Mw05Recomp"`)

Usage:
```powershell
.\run_with_debug.ps1
# Logs will be in: out\build\x64-Clang-Debug\Mw05Recomp\debug_stderr.txt
```

### Python Scripts

#### `test_baseline.py`
Writes to: `LOG_DIR\baseline_stdout.txt` and `LOG_DIR\baseline_stderr.txt`

Usage:
```bash
python test_baseline.py
# Logs will be in: out\build\x64-Clang-Debug\Mw05Recomp\baseline_*.txt
```

## 📝 IDA Pro HTTP Server API

The IDA Pro HTTP server runs on `http://127.0.0.1:5050` and provides endpoints for decompilation.

### Fetching Decompiled Code

```powershell
# Get decompiled C code
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/decompile?ea=0x8211E470').Content | Out-File -FilePath 'ida_logs\sub_8211E470_decompile.json'

# Get assembly instructions
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/disasm?ea=0x8211E470&count=50').Content | Out-File -FilePath 'ida_logs\sub_8211E470_disasm.json'

# Get raw bytes
(Invoke-WebRequest -Uri 'http://127.0.0.1:5050/bytes?ea=0x82065268&count=64').Content | Out-File -FilePath 'ida_logs\sub_82065268_bytes.json'
```

## 🧹 Cleaning Up Logs

### Manual Cleanup
```powershell
# Clean all app logs
Remove-Item out\build\x64-Clang-Debug\Mw05Recomp\*.txt

# Clean all IDA logs
Remove-Item ida_logs\*.json
```

### Automatic Cleanup
- App logs are automatically removed when you clean the build directory:
  ```powershell
  Remove-Item -Recurse -Force out\build\x64-Clang-Debug
  ```

## 📋 Best Practices

1. **Always use the log directories** - Don't write logs to the repository root
2. **Use descriptive filenames** - Include test name, timestamp, or purpose in filename
3. **Clean old logs periodically** - Logs can accumulate quickly during debugging
4. **Don't commit logs** - All log directories are in `.gitignore`
5. **Document new log locations** - Update this file if you add new logging scripts

## 🔍 Finding Logs

### Recent Test Logs
```powershell
# List all test logs sorted by date
Get-ChildItem out\build\x64-Clang-Debug\Mw05Recomp\test_*.txt | Sort-Object LastWriteTime -Descending
```

### Recent IDA Logs
```powershell
# List all IDA decompilation logs sorted by date
Get-ChildItem ida_logs\*.json | Sort-Object LastWriteTime -Descending
```

### Search Logs
```powershell
# Search for specific text in all test logs
Get-ChildItem out\build\x64-Clang-Debug\Mw05Recomp\test_*.txt | Select-String "PATTERN"

# Search for specific text in all IDA logs
Get-ChildItem ida_logs\*.json | Select-String "PATTERN"
```

## 📊 Log File Sizes

Logs can grow large during long test runs. Monitor disk usage:

```powershell
# Check total size of app logs
(Get-ChildItem out\build\x64-Clang-Debug\Mw05Recomp\*.txt | Measure-Object -Property Length -Sum).Sum / 1MB

# Check total size of IDA logs
(Get-ChildItem ida_logs\*.json | Measure-Object -Property Length -Sum).Sum / 1MB
```

## 🚀 Quick Reference

| Log Type | Location | Pattern | Committed? |
|----------|----------|---------|------------|
| Test runs | `out/build/.../Mw05Recomp/` | `test_*.txt` | ❌ No |
| Debug stderr | `out/build/.../Mw05Recomp/` | `debug_*.txt` | ❌ No |
| Codegen debug | `out/build/.../Mw05Recomp/` | `codegen_*.txt` | ❌ No |
| IDA decompile | `ida_logs/` | `sub_*_decompile.json` | ❌ No |
| IDA disasm | `ida_logs/` | `sub_*_disasm.json` | ❌ No |
| Baseline tests | `out/build/.../Mw05Recomp/` | `baseline_*.txt` | ❌ No |

