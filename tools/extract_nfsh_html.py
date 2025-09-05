# usage: python extract_nfsh_html.py NfsMWEurope.xex.html --out-toml Mw05RecompLib/config/NFSMW_EU.toml --out-switch Mw05RecompLib/config/NFSMW_switch_tables.toml

#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path
from typing import List, Tuple

# Heuristic regexes to find function labels/anchors in typical HTML exports
RE_ANCHOR = re.compile(r'(?:id|name)\s*=\s*["\']sub_([0-9A-Fa-f]{6,8})["\']')
RE_LABEL = re.compile(r">\s*(sub_([0-9A-Fa-f]{6,8}))\s*[:( ]")
# Helper names we’ll try to detect by name in the HTML
HELPER_NAMES = {
    "savegprlr_14": re.compile(r"savegprlr_14\s*\(?\)?"),
    "restgprlr_14": re.compile(r"restgprlr_14\s*\(?\)?"),
    "savefpr_14": re.compile(r"savefpr_14\s*\(?\)?"),
    "restfpr_14": re.compile(r"restfpr_14\s*\(?\)?"),
    "savevmx_14": re.compile(r"savevmx_14\s*\(?\)?"),
    "restvmx_14": re.compile(r"restvmx_14\s*\(?\)?"),
    "savevmx_64": re.compile(r"savevmx_64\s*\(?\)?"),
    "restvmx_64": re.compile(r"restvmx_64\s*\(?\)?"),
}

# Heuristic to detect function content for a given label; many HTML exports put
# function text between an anchor and the next anchor.
RE_FUNC_START = re.compile(r'(?:id|name)\s*=\s*["\']sub_([0-9A-Fa-f]{6,8})["\']')
RE_BCTR = re.compile(r"\bbctr\b", flags=re.IGNORECASE)


def parse_functions(html: str) -> List[int]:
    """Returns sorted unique function starts (addresses as ints)."""
    addrs = set()
    for m in RE_ANCHOR.finditer(html):
        addrs.add(int(m.group(1), 16))
    for m in RE_LABEL.finditer(html):
        addrs.add(int(m.group(2), 16))
    return sorted(addrs)


def derive_sizes(func_addrs: List[int]) -> List[Tuple[int, int]]:
    """Returns list of (address, size). Size is next_start - this_start (last gets 0)."""
    out = []
    for i, a in enumerate(func_addrs):
        if i + 1 < len(func_addrs):
            size = func_addrs[i + 1] - a
            # Guard against negatives or absurdly large
            if size <= 0 or size > 0x200000:
                size = 0
        else:
            size = 0
        out.append((a, size))
    return out


def find_helpers(html: str) -> dict:
    """Find helper function addresses by scanning for 'savegprlr_14' etc. near anchors."""
    helpers = {k: 0 for k in HELPER_NAMES}
    # Build a map: function start -> slice index
    starts = []
    for m in RE_FUNC_START.finditer(html):
        starts.append((m.start(), m.group(1)))
    starts.sort()
    # For each helper name, search html and backtrack to nearest preceding function anchor
    for key, rx in HELPER_NAMES.items():
        m = rx.search(html)
        if not m:
            continue
        idx = m.start()
        # find nearest preceding function start
        fn_addr = None
        for pos, hexaddr in reversed(starts):
            if pos <= idx:
                fn_addr = int(hexaddr, 16)
                break
        if fn_addr is not None:
            helpers[key] = fn_addr
    return helpers


def find_bctr_functions(html: str) -> List[int]:
    """Find functions that contain 'bctr' (as switch/jump-table candidates)."""
    # Build sections between function anchors
    sections = []
    anchors = list(RE_FUNC_START.finditer(html))
    for i, m in enumerate(anchors):
        start_pos = m.start()
        fn_hex = m.group(1)
        fn_addr = int(fn_hex, 16)
        end_pos = anchors[i + 1].start() if i + 1 < len(anchors) else len(html)
        sections.append((fn_addr, html[start_pos:end_pos]))
    out = []
    for addr, chunk in sections:
        if RE_BCTR.search(chunk):
            out.append(addr)
    return sorted(set(out))


def write_toml(
    out_path: Path, helpers: dict, funcs: List[Tuple[int, int]], switch_rel: str
):
    with out_path.open("w", encoding="utf-8") as f:
        f.write("## Need for Speed: Most Wanted (EU) – XenonRecomp config\n")
        f.write("[main]\n")
        f.write('file_path = "../private/default.xex"\n')
        f.write('patched_file_path = "../private/default_patched.xex"\n')
        f.write('out_directory_path = "../ppc"\n')
        f.write(f'switch_table_file_path = "{switch_rel}"\n\n')
        # Conservative defaults
        f.write("skip_lr = false\n")
        f.write("skip_msr = false\n")
        f.write("ctr_as_local = false\n")
        f.write("xer_as_local = false\n")
        f.write("reserved_as_local = false\n")
        f.write("cr_as_local = false\n")
        f.write("non_argument_as_local = false\n")
        f.write("non_volatile_as_local = false\n\n")
        # Helpers
        for k in (
            "restgprlr_14_address",
            "savegprlr_14_address",
            "restfpr_14_address",
            "savefpr_14_address",
            "restvmx_14_address",
            "savevmx_14_address",
            "restvmx_64_address",
            "savevmx_64_address",
        ):
            base_key = k.replace("_address", "")
            addr = helpers.get(base_key, 0)
            f.write(f"{k} = 0x{addr:08X}\n")
        f.write("\n")
        # Functions
        f.write("functions = [\n")
        for a, sz in funcs:
            # Only emit those with plausible size; leave size 0 too (analyzer may fill from .pdata)
            f.write(f"    {{ address = 0x{a:08X}, size = 0x{sz:X} }},\n")
        f.write("]\n\n")
        # Invalid instructions – leave empty to start (fill as needed)
        f.write("invalid_instructions = {}\n")


def write_switch_toml(out_path: Path, bctr_funcs: List[int]):
    with out_path.open("w", encoding="utf-8") as f:
        f.write("## NFSMW EU - tentative switch/jump table descriptors\n")
        f.write(
            "## Fill base/count/stride/targets by inspecting each function below in IDA/Ghidra\n"
        )
        f.write("switch_tables = [\n")
        for a in bctr_funcs:
            f.write("    {\n")
            f.write(f"        function = 0x{a:08X},\n")
            f.write("        base = 0x00000000,   # TODO: table base address\n")
            f.write("        count = 0,          # TODO: number of cases\n")
            f.write("        stride = 4,         # TODO: entry size\n")
            f.write("        adjust = 0,         # optional bias/correction\n")
            f.write("        # targets = [0x..., 0x..., ...],  # optional explicit\n")
            f.write("    },\n")
        f.write("]\n")


def main():
    ap = argparse.ArgumentParser(
        description="Extract NFSMW EU TOML skeleton from HTML export"
    )
    ap.add_argument("html", type=Path, help="Path to NfsMWEurope.xex.html export")
    ap.add_argument("--out-toml", type=Path, default=Path("NFSMW_EU.toml"))
    ap.add_argument("--out-switch", type=Path, default=Path("NFSMW_switch_tables.toml"))
    args = ap.parse_args()

    if not args.html.exists():
        print(f"ERROR: {args.html} not found", file=sys.stderr)
        sys.exit(1)

    text = args.html.read_text(encoding="utf-8", errors="ignore")

    funcs = parse_functions(text)
    if not funcs:
        print("WARNING: no function anchors found; check HTML format", file=sys.stderr)

    funcs_with_sizes = derive_sizes(funcs)
    helpers = find_helpers(text)
    bctr_funcs = find_bctr_functions(text)

    # Switch file path relative to TOML
    switch_rel = (
        args.out_switch.name
        if args.out_switch.parent == args.out_toml.parent
        else str(args.out_switch)
    )

    args.out_toml.parent.mkdir(parents=True, exist_ok=True)
    write_toml(args.out_toml, helpers, funcs_with_sizes, switch_rel)

    args.out_switch.parent.mkdir(parents=True, exist_ok=True)
    write_switch_toml(args.out_switch, bctr_funcs)

    print(f"Wrote {args.out_toml} and {args.out_switch}")
    print(
        f"Functions found: {len(funcs_with_sizes)}; bctr candidates: {len(bctr_funcs)}"
    )
    print(
        "NOTE: Review helper addresses and switch tables; fill accurate values from IDA/Ghidra."
    )


if __name__ == "__main__":
    main()
