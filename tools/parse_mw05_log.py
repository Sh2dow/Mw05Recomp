#!/usr/bin/env python3
"""
Parse mw05_debug.log (or any log containing KernelTraceImport output) and extract
guest caller LR addresses for HOST.* GPU calls, then emit suggested
GUEST_FUNCTION_HOOK lines to add under the MW05 block in gpu/video.cpp.

Usage:
  python tools/parse_mw05_log.py mw05_debug.log

It prints a de-duplicated, sorted list like:
  # HOST.SetRenderTarget
  GUEST_FUNCTION_HOOK(sub_8259ABCD, SetRenderTarget);
  ...
Copy the lines into the MW05 hooks region in Mw05Recomp/gpu/video.cpp.
"""
import re
import sys
from pathlib import Path

HOST_MAP = {
    'HOST.SetRenderTarget': 'SetRenderTarget',
    'HOST.SetDepthStencilSurface': 'SetDepthStencilSurface',
    'HOST.Clear': 'Clear',
    'HOST.SetViewport': 'SetViewport',
    'HOST.SetTexture': 'SetTexture',
    'HOST.SetScissorRect': 'SetScissorRect',
    'HOST.DrawPrimitive': 'DrawPrimitive',
    'HOST.DrawIndexedPrimitive': 'DrawIndexedPrimitive',
    'HOST.DrawPrimitiveUP': 'DrawPrimitiveUP',
}

def parse_log(path: Path):
    text = path.read_text(encoding='utf-8', errors='ignore')
    # Example line:
    # [TRACE] import=HOST.SetRenderTarget tid=XXXXXXXX lr=0x8259ABCD r3=...
    # Support both logger format and fallback host file format
    rx = re.compile(r"(?:import=|import=)(HOST\.[A-Za-z0-9_]+).*?lr=0x([0-9A-Fa-f]{8})")
    hits = {}
    for m in rx.finditer(text):
        host = m.group(1)
        lr = m.group(2).upper()
        if host in HOST_MAP:
            hits.setdefault(host, set()).add(lr)
    return hits

def main(argv):
    if len(argv) < 2:
        print("usage: parse_mw05_log.py <logfile>")
        return 2
    p = Path(argv[1])
    if not p.exists():
        print(f"error: file not found: {p}")
        return 2
    hits = parse_log(p)
    # Also look for a sidecar host trace file if no hits and default path exists
    if not hits:
        from os import getenv
        sidecar = Path(getenv('MW05_HOST_TRACE_FILE') or 'mw05_host_trace.log')
        if sidecar.exists():
            print(f"(no hits in {p.name}; scanning {sidecar.name})")
            hits = parse_log(sidecar)
    count = 0
    for host in sorted(hits.keys()):
        func = HOST_MAP[host]
        print(f"# {host}")
        for lr in sorted(hits[host]):
            print(f"GUEST_FUNCTION_HOOK(sub_{lr}, {func});")
            count += 1
        print()
    print(f"# total hooks suggested: {count}")
    return 0

if __name__ == '__main__':
    sys.exit(main(sys.argv))
