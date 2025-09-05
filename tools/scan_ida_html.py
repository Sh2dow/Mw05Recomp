#!/usr/bin/env python3
# Simple IDA HTML scanner for function names and text snippets.
# - What it does: parses your …xex.html to list functions(e.g., sub_826BE6F0)and optionally finds those “nearby”(same prefix / range)or containing a text snippet like “data = 0x00000000, size = 4”.
# - Use it to confirm whether the missing sub_826BE6F0 / F8 / 700 / 704 exist in the dump and inspect neighbors.

# Usage:
#   python tools/scan_ida_html.py "f:\XBox\Recomp\MW05\NfsMWEurope.xex.html" --dump-func 826BE708 --context 1500
#   python tools/scan_ida_html.py "f:\XBox\Recomp\MW05\NfsMWEurope.xex.html" --locate 826BE6F

import re
import sys
import argparse
from pathlib import Path
import html as _html
from typing import List, Tuple


def parse_funcs(text: str) -> List[Tuple[str, int]]:
    # Matches common IDA HTML anchors/text like sub_XXXXXXXX
    rx = re.compile(r"sub_([0-9A-Fa-f]{8})")
    found = []
    for m in rx.finditer(text):
        addr_hex = m.group(1).upper()
        found.append(("sub_" + addr_hex, int(addr_hex, 16)))
    # De-dupe by name, keep highest address seen, then sort by address
    uniq = {}
    for name, addr in found:
        uniq[name] = addr
    return sorted(uniq.items(), key=lambda x: x[1])


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan IDA HTML for functions and snippets")
    ap.add_argument("html", type=Path, help="Path to IDA HTML export (e.g. NfsMWEurope.xex.html)")
    ap.add_argument("--find", help="Hex address (e.g. 826BE6F0) or prefix (e.g. 826BE6)")
    ap.add_argument("--grep", help="Find a literal text snippet in the HTML")
    ap.add_argument("--grep-strip", action="store_true", help="Strip HTML tags before performing grep/regex searches")
    ap.add_argument("--grep-regex", help="Search using a regular expression (use with --grep-strip to match logical text)")
    ap.add_argument("--context", type=int, default=120, help="Context characters to show around regex matches (default: 120)")
    ap.add_argument("--ignore-case", action="store_true", help="Case-insensitive regex search")
    ap.add_argument("--unescape", action="store_true", help="Unescape HTML entities (e.g., &nbsp;) before searching")
    ap.add_argument("--dump-func", help="Dump context around a function anchor (e.g., 826BE660 or sub_826BE660)")
    ap.add_argument("--locate", help="Locate which function range contains the given hex address (uses .pdata Function start/end)")
    ap.add_argument("--json", type=Path, help="Write the full symbol list as JSON")
    args = ap.parse_args()

    txt = args.html.read_text(encoding="utf-8", errors="ignore")

    funcs = parse_funcs(txt)
    if args.json:
        try:
            import json
        except Exception:
            print("error: json module not available", file=sys.stderr)
            return 2
        args.json.write_text(json.dumps([{"name": n, "addr": a} for n, a in funcs], indent=2))

    if args.find:
        key = args.find.upper()

        def match(name: str, addr: int) -> bool:
            if len(key) == 8:
                return f"{addr:08X}" == key
            return f"{addr:08X}".startswith(key)

        hits = [(n, a) for n, a in funcs if match(n, a)]
        print(f"Matches for {key}:")
        for n, a in hits:
            print(f"  {n} @ 0x{a:08X}")
        # Show neighbors around exact match
        if len(key) == 8 and hits:
            idx = [i for i, (n, a) in enumerate(funcs) if f"{a:08X}" == key][0]
            start = max(0, idx - 5)
            end = min(len(funcs), idx + 6)
            print("Neighbors:")
            for i in range(start, end):
                n, a = funcs[i]
                print(("> " if i == idx else "  ") + f"{n} @ 0x{a:08X}")

    # Choose search text (raw or stripped)
    search_text = txt
    if args.grep_strip:
        # Replace HTML tags with spaces to keep rough line positioning
        search_text = re.sub(r"<[^>]+>", " ", search_text)
    if args.unescape:
        # Decode HTML entities (e.g., &nbsp;, &amp;) so literal/regex searches work
        search_text = _html.unescape(search_text)

    if args.grep:
        print(f"Searching for text: {args.grep!r} (strip_tags={args.grep_strip})")
        for i, line in enumerate(search_text.splitlines(), 1):
            if args.grep in line:
                print(f"{i:6d}: {line.strip()}")

    if args.grep_regex:
        print(f"Searching regex: {args.grep_regex!r} (strip_tags={args.grep_strip}, unescape={args.unescape}, ignore_case={args.ignore_case})")
        flags = re.IGNORECASE if args.ignore_case else 0
        rx = re.compile(args.grep_regex, flags)
        for m in rx.finditer(search_text):
            start, end = m.start(), m.end()
            # Compute line number by counting newlines up to start
            line_no = search_text.count("\n", 0, start) + 1
            s = max(0, start - max(0, args.context))
            e = min(len(search_text), end + max(0, args.context))
            snippet = search_text[s:e].replace("\n", " ")
            print(f"line={line_no} start={start} end={end} snippet=…{snippet}…")

    if args.dump_func:
        key = args.dump_func
        # Normalize key to sub_XXXXXXXX form
        if not key.startswith("sub_"):
            try:
                key = f"sub_{int(key, 16):08X}"
            except Exception:
                pass
        print(f"Dumping around anchor: {key} (strip_tags={args.grep_strip}, unescape={args.unescape})")
        idx = search_text.find(key)
        if idx < 0 and search_text is not txt:
            # Try raw HTML as fallback
            idx = txt.find(key)
            if idx >= 0:
                search_text = txt
        if idx < 0:
            print("Anchor not found.")
        else:
            line_no = search_text.count("\n", 0, idx) + 1
            s = max(0, idx - max(0, args.context))
            e = min(len(search_text), idx + len(key) + max(0, args.context))
            snippet = search_text[s:e]
            print(f"line={line_no} start={idx} end={idx+len(key)}")
            print("----- snippet start -----")
            print(snippet)
            print("----- snippet end -----")

    if args.locate:
        # Build function ranges by scanning .pdata comments: "# Function start" and following "# Function end: XXXXXXXX"
        addr_hex = args.locate.upper()
        try:
            addr_val = int(addr_hex, 16)
        except Exception:
            print(f"Invalid --locate address: {args.locate}")
            addr_val = None

        # Line-based scan of raw HTML for start/end hints
        ranges = []
        start_name = None
        start_addr = None
        for line in txt.splitlines():
            # Look for a start marker
            mstart = re.search(r"sub_([0-9A-Fa-f]{8}).*#\s*Function start", line)
            if mstart:
                start_name = "sub_" + mstart.group(1).upper()
                start_addr = int(mstart.group(1), 16)
                continue
            # If in a function, look for the next end marker
            if start_name is not None:
                mend = re.search(r"Function end:\s*([0-9A-Fa-f]{8})", line)
                if mend:
                    end_addr = int(mend.group(1), 16)
                    ranges.append((start_name, start_addr, end_addr))
                    start_name = None
                    start_addr = None

        print(f"Loaded {len(ranges)} function ranges from .pdata")
        if addr_val is not None:
            # Find containing, otherwise nearest neighbors
            containing = [(n, s, e) for (n, s, e) in ranges if s <= addr_val <= e]
            if containing:
                n, s, e = containing[0]
                print(f"0x{addr_val:08X} is inside {n} [0x{s:08X} .. 0x{e:08X}]")
            else:
                # Find nearest previous and next ranges
                prev = max(((n, s, e) for (n, s, e) in ranges if e <= addr_val), default=None, key=lambda t: t[2])
                nxt = min(((n, s, e) for (n, s, e) in ranges if s >= addr_val), default=None, key=lambda t: t[1])
                print(f"0x{addr_val:08X} not inside any range")
                if prev:
                    print(f"  prev: {prev[0]} [0x{prev[1]:08X} .. 0x{prev[2]:08X}]")
                if nxt:
                    print(f"  next: {nxt[0]} [0x{nxt[1]:08X} .. 0x{nxt[2]:08X}]")

    # If neither flag used, just print a short summary
    if not args.find and not args.grep and not args.grep_regex and not args.dump_func and not args.locate and not args.json:
        print(f"Parsed {len(funcs)} functions from {args.html}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
