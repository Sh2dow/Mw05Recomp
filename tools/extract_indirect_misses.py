#!/usr/bin/env python3
import argparse
import os
import re
import sys
from typing import List, Set

MISS_RE = re.compile(r"\[ppc\]\[indirect-miss\]\s+target=0x([0-9A-Fa-f]{8})")

def parse_args():
    ap = argparse.ArgumentParser(description="Extract unique indirect-miss targets from mw05_debug.log")
    ap.add_argument("--log", required=True, help="Path to mw05_debug.log")
    ap.add_argument("--out", required=True, help="Output text file with one hex address per line")
    ap.add_argument("--merge", action="store_true", help="Accumulate with existing out file across runs")
    return ap.parse_args()

def read_log(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except FileNotFoundError:
        return []

def extract_misses(lines: List[str]) -> List[str]:
    seen: Set[int] = set()
    order: List[int] = []
    for line in lines:
        m = MISS_RE.search(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        # Filter to expected title address space to avoid noise
        if not (0x82000000 <= addr <= 0x8FFFFFFF):
            continue
        if addr not in seen:
            seen.add(addr)
            order.append(addr)
    # sort for stability, but keep insertion order as tiebreaker if needed
    return [f"0x{a:08X}" for a in sorted(order)]

def write_if_changed(out_path: str, lines: List[str]) -> None:
    new = "\n".join(lines) + ("\n" if lines else "")
    old = None
    try:
        with open(out_path, "r", encoding="utf-8", errors="ignore") as f:
            old = f.read()
    except FileNotFoundError:
        old = None
    if old == new:
        return
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(new)
    os.replace(tmp, out_path)

def main():
    args = parse_args()
    lines = read_log(args.log)
    misses = set(extract_misses(lines))
    if args.merge and os.path.exists(args.out):
        try:
            with open(args.out, "r", encoding="utf-8", errors="ignore") as f:
                for l in f:
                    l = l.strip()
                    if l.startswith("0x"):
                        misses.add(l)
        except Exception:
            pass
    merged = sorted(misses)
    write_if_changed(args.out, merged)
    # Print a short summary to help CMake/Ninja logs
    print(f"[extract_indirect_misses] {len(merged)} unique addresses -> {args.out}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
