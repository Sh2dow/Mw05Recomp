#!/usr/bin/env python3
"""
Scan Mw05Recomp sources for PPC_FUNC(sub_XXXXXXXX) and emit a CSV skeleton
you can fill with MW-specific guest addresses when they differ.

Output columns: name,unleashed_addr
"""

import argparse
import re
from pathlib import Path


def scan_hooks(src_root: Path):
    rx = re.compile(r"PPC_FUNC\s*\(\s*(sub_([0-9A-Fa-f]{8}))\s*\)")
    items = []
    for p in (src_root).rglob('*.cpp'):
        txt = p.read_text(encoding='utf-8', errors='ignore')
        for m in rx.finditer(txt):
            items.append((m.group(1), int(m.group(2), 16), str(p)))
    # De-dupe by name
    seen = set()
    out = []
    for name, addr, path in sorted(items, key=lambda t: t[1]):
        if name in seen:
            continue
        seen.add(name)
        out.append((name, addr))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description='Dump app PPC hooks into CSV skeleton')
    ap.add_argument('--src-root', type=Path, default=Path('Mw05Recomp'))
    ap.add_argument('--out-csv', type=Path, default=Path('tools/hooks_unleashed.csv'))
    args = ap.parse_args()

    hooks = scan_hooks(args.src_root)
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.out_csv.open('w', encoding='utf-8') as f:
        f.write('name,unleashed_addr\n')
        for name, addr in hooks:
            f.write(f'{name},0x{addr:08X}\n')
    print(f'Wrote {args.out_csv} with {len(hooks)} hooks')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

