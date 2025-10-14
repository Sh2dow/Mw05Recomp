r"""
usage:
  python .\Auto_Function_Parser.py f:\XBox\Recomp\MW05\NfsMWEurope.xex.html out_tdb.txt mw05_switch_tables.toml \
         --addr-range 0x82000000-0x83FFFFFF --min-size 0x20 --segment ".text"

Additional flags for safer batches (defaults keep legacy behavior):
  --max-size 0x4000          Skip functions larger than this (default: off)
  --enforce-align             Require 0x10 alignment for start address (default: off)
  --no-overlap                Drop functions overlapping already accepted ones (default: off)
  --batch-size N              Emit only first N by safety ranking (default: all)
"""

import sys, re

USAGE = """\
Auto_Function_Parser.py [IDA HTML] [XenonRecomp log] [Output TOML]
  [--addr-range 0xLOW-0xHIGH]
  [--min-size 0xNN]
  [--segment ".text"]           # keep only this section (optional)
  [--no-dump-all]               # do NOT dump all when no switches are found
"""

if len(sys.argv) < 4:
    sys.exit(USAGE)

ida_html = sys.argv[1]
xenonrecomp_log = sys.argv[2]
output_file = sys.argv[3]

# Defaults
addr_range = None
min_size = 0
max_size = None
segment_name = None
dump_all_if_no_switch = True  # <-- default ON
enforce_align = False
no_overlap = False
batch_size = None

# Parse flags
i = 4
while i < len(sys.argv):
    tok = sys.argv[i]
    if tok == "--addr-range" and (i + 1) < len(sys.argv):
        lo, hi = sys.argv[i+1].split("-", 1)
        addr_range = (int(lo, 16), int(hi, 16))
        i += 2; continue
    if tok == "--min-size" and (i + 1) < len(sys.argv):
        min_size = int(sys.argv[i+1], 16)
        i += 2; continue
    if tok == "--max-size" and (i + 1) < len(sys.argv):
        max_size = int(sys.argv[i+1], 16)
        i += 2; continue
    if tok == "--segment" and (i + 1) < len(sys.argv):
        segment_name = sys.argv[i+1]
        i += 2; continue
    if tok == "--enforce-align":
        enforce_align = True
        i += 1; continue
    if tok == "--no-overlap":
        no_overlap = True
        i += 1; continue
    if tok == "--batch-size" and (i + 1) < len(sys.argv):
        try:
            batch_size = int(sys.argv[i+1], 0)
        except ValueError:
            batch_size = None
        i += 2; continue
    if tok == "--no-dump-all":
        dump_all_if_no_switch = False
        i += 1; continue
    i += 1

print("Parsing XenonRecomp log...")
switch_addrs = set()
pats = [
    re.compile(r'ERROR:\s*Switch case at\s*(?:0x)?([0-9A-Fa-f]{6,8})'),
    re.compile(r'(?:error|ERROR).*?(?:switch|Switch).*?(?:at|@)\s*(?:0x)?([0-9A-Fa-f]{6,8})'),
    re.compile(r'(?:warning|WARN).*?(?:switch|Switch).*?(?:at|@)\s*(?:0x)?([0-9A-Fa-f]{6,8})'),
]
with open(xenonrecomp_log, 'r', errors='ignore') as f:
    for line in f:
        for p in pats:
            m = p.search(line)
            if m:
                switch_addrs.add(m.group(1).upper())
                break

print("Parsing IDA HTML (anchor-based)...")
with open(ida_html, 'r', errors='ignore') as f:
    html = f.read()

# Find anchors/tokens for function starts
anchor_pat = re.compile(r'(?:id|name)\s*=\s*"(?:sub|fn|unknown|__)?_([0-9A-Fa-f]{6,8})"', re.IGNORECASE)
anchors = [(m.start(), m.group(1).upper()) for m in anchor_pat.finditer(html)]

if not anchors:
    token_pat = re.compile(r'\b(?:sub|fn|unknown|__)?_([0-9A-Fa-f]{6,8})\b')
    anchors = [(m.start(), m.group(1).upper()) for m in token_pat.finditer(html)]

# Order & dedup
seen = set()
ordered = [(pos, int(addr, 16)) for pos, addr in sorted(anchors, key=lambda x: x[0]) if not (addr in seen or seen.add(addr))]

if ordered:
    amin = min(a for _, a in ordered); amax = max(a for _, a in ordered)
    print(f"Anchors/tokens: count={len(ordered)}, min=0x{amin:08X}, max=0x{amax:08X}")
else:
    print("Anchors/tokens: count=0")

# Optional: section filter (opt-in)
if segment_name:
    # Section header tolerant to tags and quotes (&quot; or ")
    sec_pat = re.compile(r'(?is)\.section(?:\s|<[^>]+>)*(?:&quot;|")\s*(?:<[^>]+>)*([.\w$]+)\s*(?:<[^>]+>)*(?:&quot;|")')
    spans = [(m.start(), m.group(1)) for m in sec_pat.finditer(html)]
    spans.sort(key=lambda x: x[0])
    ranges = []
    for idx, (pos, name) in enumerate(spans):
        end = spans[idx+1][0] if idx + 1 < len(spans) else len(html)
        ranges.append((pos, end, name))

    def in_section(pos, target):
        t = target.strip().lower()
        for s, e, nm in ranges:
            if s <= pos < e:
                n = (nm or "").strip().lower()
                if n == t or n.endswith(t.strip(".")):
                    return True
                return False
        return False

    before = len(ordered)
    ordered = [(pos, a) for (pos, a) in ordered if in_section(pos, segment_name)]
    print(f"Section '{segment_name}': {len(ordered)} (was {before})")

# Optional: address range
if addr_range:
    lo, hi = addr_range
    before = len(ordered)
    ordered = [(pos, a) for (pos, a) in ordered if lo <= a <= hi]
    print(f"Addr-range {addr_range!r}: {len(ordered)} (was {before})")

# Build function ranges
functs = []
for i, (_, start_int) in enumerate(ordered):
    if i + 1 < len(ordered):
        next_start_int = ordered[i+1][1]
        end_int = max(start_int + 4, next_start_int - 4)
    else:
        end_int = start_int + 0x40
    functs.append([start_int, end_int])

def _size(f):
    return f[1] - f[0]

# Min-size / Max-size / Alignment
if min_size:
    before = len(functs)
    functs = [f for f in functs if _size(f) >= min_size]
    print(f"Min-size 0x{min_size:X}: {len(functs)} (was {before})")
if max_size is not None:
    before = len(functs)
    functs = [f for f in functs if _size(f) <= max_size]
    print(f"Max-size 0x{max_size:X}: {len(functs)} (was {before})")
if enforce_align:
    before = len(functs)
    functs = [f for f in functs if (f[0] % 16) == 0]
    print(f"Alignment (16B) kept: {len(functs)} (was {before})")

# Sort by start then size for deterministic overlap pass
functs.sort(key=lambda f: (f[0], _size(f)))

if no_overlap and functs:
    compact = []
    last_end = -1
    for s, e in functs:
        if s >= last_end:
            compact.append([s, e])
            last_end = e
    print(f"Overlap removal: {len(compact)} (was {len(functs)})")
    functs = compact

# Map or dump-all
print("Searching for needed functions...")
output = []

if not switch_addrs:
    print("No switch addresses parsed from XenonRecomp log.")
    if dump_all_if_no_switch and functs:
        print("Dumping ALL parsed functions (fallback).")
        for start, end in functs:
            output.append([hex(start), hex(end - start)])
    else:
        print("Skip dump-all (flag disabled).")
else:
    for sw in switch_addrs:
        sw_i = int(sw, 16)
        for start, end in functs:
            if start < sw_i <= end:
                output.append([hex(start), hex(end - start)])
                break

# Dedup
output = list({tuple(x) for x in output})

if output:
    omin = min(int(s, 16) for s, _ in output)
    omax = max(int(s, 16) for s, _ in output)
    print(f"Output: count={len(output)}, min=0x{omin:08X}, max=0x{omax:08X}")
else:
    print("Output: count=0")

print(f"{len(output)} functions found!")
print("Outputting to formatted file...")

# Prefer smaller first (safer), then address
output.sort(key=lambda t: (int(t[1], 16), int(t[0], 16)))
if batch_size:
    print(f"Batch-size in effect: {batch_size}")
    output = output[:batch_size]

parts = ["functions = ["]
for start_hex, size_hex in output:
    parts.append(f"\n    {{ address = 0x{start_hex[2:].upper()}, size = 0x{size_hex[2:].upper()} }},")
if len(parts) > 1:
    parts[-1] = parts[-1].rstrip(',')
parts.append("\n]")
toml = "".join(parts)

with open(output_file, "w") as f:
    f.write(toml)

print(f"Wrote TOML to: {output_file}")
