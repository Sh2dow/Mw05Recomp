#!/usr/bin/env python3
"""
mw_heap_crossref.py

Given a HOST.* trace log, locate sentinel observations (0x0A000000) and
cross-reference preceding HOST.Store64BE_W writes to infer struct clears.
Optionally filter/anchor by specific heap base addresses seen in the log.

Usage:
  python mw_heap_crossref.py log.txt --heaps B56A06F0 B56A0B40 --context 120 --cluster-gap 24

Outputs a human-friendly report mapping clusters to base/size and lists
offsets (+0xNN) for each write, highlighting entries near watchEA (block+0x10).

You can paste these offsets into IDA to define struct fields.
"""

import re
import sys
import argparse
from collections import namedtuple

Store64 = namedtuple("Store64", "line ea val")
Sentinel = namedtuple("Sentinel", "line kind block watch lr src")

HEX32 = r"[0-9A-F]{8}"
HEX64 = r"[0-9A-F]{16}"
HEXLR = r"[0-9A-F]+"

RE_STORE64 = re.compile(rf"HOST\.Store64BE_W\.called ea=(?P<ea>{HEX32}) val=(?P<val>{HEX64})", re.IGNORECASE)
RE_WATCH_ANY = re.compile(rf"HOST\.watch\.any(?:\((?P<phase>pre|read)\))?\s+val=0A000000\s+ea=(?P<ea>{HEX32})\s+lr=(?P<lr>{HEXLR})", re.IGNORECASE)
RE_WAIT_BLOCK = re.compile(rf"HOST\.sub_826346A8\.block .* ea=(?P<block>{HEX32}).* w4=(?P<w4>{HEX32})", re.IGNORECASE)

def to_u32(s): return int(s, 16)
def to_u64(s): return int(s, 16)

def group_clusters(stores, gap):
    clusters = []
    cur = []
    last = None
    for s in stores:
        if not cur:
            cur = [s]; last = s.ea; continue
        if s.ea >= last and (s.ea - last) <= gap:
            cur.append(s); last = s.ea
        else:
            clusters.append(cur); cur = [s]; last = s.ea
    if cur: clusters.append(cur)
    return clusters

def summarize_cluster(cluster):
    base = cluster[0].ea
    last = cluster[-1].ea
    size = (last - base) + 8
    clears = sum(1 for s in cluster if s.val == 0)
    return {"base": base, "size": size, "writes": len(cluster), "clears": clears, "entries": cluster}

def scan(log_lines, context, gap, heap_filters):
    # collect all Store64
    stores = []
    for i, line in enumerate(log_lines):
        m = RE_STORE64.search(line)
        if m:
            stores.append(Store64(i, to_u32(m.group("ea")), to_u64(m.group("val"))))

    # collect sentinel reads (watch.any and waiter blocks)
    sents = []
    for i, line in enumerate(log_lines):
        m = RE_WATCH_ANY.search(line)
        if m:
            ea = to_u32(m.group("ea"))
            lr = m.group("lr")
            sents.append(Sentinel(i, "watch.any", ea-0x10, ea, lr, line.strip()))
        m2 = RE_WAIT_BLOCK.search(line)
        if m2 and m2.group("w4").upper() == "0A000000":
            block = to_u32(m2.group("block"))
            sents.append(Sentinel(i, "wait.observe", block, block+0x10, "0", line.strip()))

    # For each sentinel, look back and cluster stores; filter by heaps if provided
    out = []
    for s in sents:
        window = [st for st in stores if s.line - context <= st.line < s.line]
        clusters = [summarize_cluster(c) for c in group_clusters(window, gap)]
        if heap_filters:
            hf = set(int(x,16) for x in heap_filters)
            clusters = [c for c in clusters if c["base"] in hf]
        # pick clusters that cover the watch or keep all if filtering
        out.append((s, clusters))
    return out

def hx(x): return f"0x{x:08X}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--context", type=int, default=80)
    ap.add_argument("--cluster-gap", type=int, default=24)
    ap.add_argument("--heaps", nargs="*", default=[], help="Optional base EAs to focus on (e.g., B56A06F0 B56A0B40)")
    args = ap.parse_args()

    with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    results = scan(lines, args.context, args.cluster_gap, args.heaps)

    print("="*90)
    print(f"Sentinel events found: {len(results)}")
    for s, clusters in results:
        print("-"*90)
        print(f"{s.kind}@{s.line}: LR={s.lr} block={hx(s.block)} watch={hx(s.watch)}")
        print(f"Src: {s.src}")
        if not clusters:
            print("  (no Store64 clusters in context / after filtering)")
            continue
        for i, c in enumerate(clusters, 1):
            print(f"  [{i}] base={hx(c['base'])} size={c['size']:>5}B writes={c['writes']:>3} clears={c['clears']:>3}")
            # offsets list
            for e in c["entries"][:12]:
                off = e.ea - c["base"]
                print(f"       +{off:04X} ea={hx(e.ea)} val={e.val:016X}")
            more = len(c["entries"]) - 12
            if more > 0:
                print(f"       ... (+{more} more)")
            # if watch lies in this range, print its offset from base
            if c["base"] <= s.watch < (c["base"] + c["size"]):
                print(f"       watch offset within cluster base: +{(s.watch - c['base']):04X}")
        print()

if __name__ == "__main__":
    main()
