# Logging & Traces (Consolidated)

## Where
- out/build/x64-Clang-Debug/Mw05Recomp/
- traces/ (large session logs)
- ida_logs/ (IDA HTTP outputs)

## Verbosity control (zero-cost when off)
Header: Mw05Recomp/kernel/debug_verbosity.h
- MW05_DEBUG_GRAPHICS=0|1|2|3
- MW05_DEBUG_KERNEL=0|1|2|3
- MW05_DEBUG_THREAD=0|1|2|3
- MW05_DEBUG_HEAP=0|1|2|3
- MW05_DEBUG_FILEIO=0|1|2|3
- MW05_DEBUG_PM4=0|1|2|3

## Common actions
- Run timed debug: `python scripts/auto_handle_messageboxes.py --duration 30`
- PM4 histogram: set `MW05_PM4_TRACE=1`, then grep `HOST.PM4.OPC`
- Tail recent: `Get-ChildItem out/build/.../Mw05Recomp/*.txt | Sort-Object LastWriteTime -Desc | Select-Object -First 5`

## Cleanup
- `Remove-Item out/build/x64-Clang-Debug/Mw05Recomp/*.txt`
- `Remove-Item ida_logs/*.json`

## Keep for provenance
- LOGGING.md (archived)
