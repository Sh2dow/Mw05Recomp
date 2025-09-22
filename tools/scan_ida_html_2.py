#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDA HTML scanner for function anchors and text snippets.

Examples:
  python tools/scan_ida_html.py NfsMWEurope.xex.html --locate 0x82813514
  python tools/scan_ida_html.py NfsMWEurope.xex.html --dump-func 826BE708 --context 1500
  python tools/scan_ida_html.py NfsMWEurope.xex.html --near 826BE6
  python tools/scan_ida_html.py NfsMWEurope.xex.html --grep "data = 0x00000000, size = 4" --context 400
"""

import argparse
import re
import sys
from typing import List, Tuple, Dict, Optional

Func = Tuple[int, int]   # (addr, text_offset)

SUB_ANCHOR_RE = re.compile(
    r'(?:<a\s+name="sub_([0-9A-Fa-f]{8})"|\\bsub_([0-9A-Fa-f]{8})\\b)',
    re.IGNORECASE
)

HEX_RE = re.compile(r'0x[0-9A-Fa-f]+|[0-9A-Fa-f]+')


def parse_hex(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 16)


def load_html(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def build_func_index(html: str) -> List[Func]:
    """Return sorted list of (addr, offset) from sub_XXXXXXXX anchors/names."""
    seen: Dict[int, int] = {}
    for m in SUB_ANCHOR_RE.finditer(html):
        addr_hex = m.group(1) or m.group(2)
        if not addr_hex:
            continue
        addr = int(addr_hex, 16)
        # first occurrence (closest to anchor) is good enough
        if addr not in seen:
            seen[addr] = m.start()
    funcs = sorted((addr, off) for addr, off in seen.items())
    return funcs


def locate_address(funcs: List[Func], addr: int) -> Optional[Tuple[int, int, Optional[int]]]:
    """
    Given an address, find the function that contains it by start <= addr < next_start.
    Returns (func_addr, start_offset, next_func_addr|None)
    """
    if not funcs:
        return None
    lo, hi = 0, len(funcs) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        fa, _ = funcs[mid]
        if fa == addr:
            best = mid
            break
        if fa < addr:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        return None
    cur_addr, cur_off = funcs[best]
    next_addr = funcs[best + 1][0] if best + 1 < len(funcs) else None
    if next_addr is not None and addr >= next_addr:
        # addr actually falls after this func start; report next
        return funcs[best + 1][0], funcs[best + 1][1], funcs[best + 2][0] if best + 2 < len(funcs) else None
    return (cur_addr, cur_off, next_addr)


def dump_context(html: str, center_offset: int, context: int) -> str:
    s = max(0, center_offset - context)
    e = min(len(html), center_offset + context)
    out = html[s:e]
    # make it a bit nicer to read in terminal
    return out.replace("\r", "")


def find_anchor_offset(html: str, addr: int) -> Optional[int]:
    # prefer exact anchor <a name="sub_XXXXXXXX">
    anchor = f'name="sub_{addr:08X}"'
    i = html.find(anchor)
    if i >= 0:
        return i
    # fall back to first textual occurrence
    label = f"sub_{addr:08X}"
    j = html.find(label)
    return j if j >= 0 else None


def do_locate(html: str, funcs: List[Func], addr: int, context: int) -> int:
    res = locate_address(funcs, addr)
    if not res:
        print("No functions indexed or address out of range.")
        return 1
    func_addr, _, next_addr = res
    print(f"0x{addr:08X} is inside sub_{func_addr:08X} "
          f"[0x{func_addr:08X} .. 0x{(next_addr or 0):08X}]" if next_addr
          else f"[0x{func_addr:08X} .. end]")
    # also show a nearby snippet
    off = find_anchor_offset(html, func_addr)
    if off is not None:
        snippet = dump_context(html, off, context // 4)
        print("\n--- context (trimmed) ---\n")
        print(snippet)
    return 0


def do_dump_func(html: str, addr: int, context: int) -> int:
    off = find_anchor_offset(html, addr)
    if off is None:
        print(f"Anchor for sub_{addr:08X} not found.")
        return 1
    print(f"Dumping around sub_{addr:08X} @ byte offset {off} (±{context} chars)\n")
    print(dump_context(html, off, context))
    return 0


def do_grep(html: str, needle: str, context: int, max_hits: int) -> int:
    cnt = 0
    for m in re.finditer(re.escape(needle), html, flags=re.IGNORECASE):
        cnt += 1
        s = dump_context(html, m.start(), context)
        print(f"\n== hit {cnt} at byte {m.start()} ==\n{s}\n")
        if 0 < max_hits <= cnt:
            break
    if cnt == 0:
        print("No matches.")
        return 1
    return 0


def do_near(funcs: List[Func], prefix: str, limit: int) -> int:
    prefix = prefix.upper()
    if prefix.startswith("0X"):
        prefix = prefix[2:]
    if not re.fullmatch(r"[0-9A-F]{1,8}", prefix):
        print("Prefix must be hex (e.g. 826BE6).")
        return 1
    hits = [(addr, off) for addr, off in funcs if f"{addr:08X}".startswith(prefix)]
    if not hits:
        print("No sub_ matches for that prefix.")
        return 1
    for i, (addr, _) in enumerate(hits[:limit], 1):
        print(f"{i:3d}. sub_{addr:08X}")
    return 0


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Scan IDA HTML for sub_XXXXXXXX anchors and snippets.")
    ap.add_argument("html", help="Path to IDA .html export")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--locate", help="Address (hex) to locate (e.g. 0x82813514 or 82813514)")
    g.add_argument("--dump-func", dest="dump_func", help="Dump around sub_<hex> anchor")
    g.add_argument("--grep", help="Case-insensitive text search")
    g.add_argument("--near", help="List functions whose name starts with this hex prefix (e.g. 826BE6)")
    ap.add_argument("--context", type=int, default=800, help="Context chars for dumps (default 800)")
    ap.add_argument("--max-hits", type=int, default=20, help="Max grep hits to print (default 20)")
    ap.add_argument("--limit", type=int, default=50, help="Limit for --near listing (default 50)")
    args = ap.parse_args(argv)

    html = load_html(args.html)
    funcs = build_func_index(html)
    print(f"Loaded {len(funcs)} function anchors from HTML.")

    if args.locate:
        addr = parse_hex(args.locate)
        return do_locate(html, funcs, addr, args.context)
    if args.dump_func:
        addr = parse_hex(args.dump_func)
        return do_dump_func(html, addr, args.context)
    if args.grep:
        return do_grep(html, args.grep, args.context, args.max_hits)
    if args.near:
        return do_near(funcs, args.near, args.limit)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
