# Usage: python tools/find_missing_ppc_symbols.py
# This regenerates ppc_missing_stubs.cpp to cover any outstanding gaps. Commit/rebuild to resolve link errors fast.

#!/usr/bin/env python3
# Compare mapping references against generated recompiler TUs and emit stubs for missing ones.

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "Mw05RecompLib" / "ppc"
MAP = ROOT / "ppc_func_mapping.cpp"
STUB = ROOT / "ppc_missing_stubs.cpp"


def need_symbols():
    rx = re.compile(r"\{\s*0x[0-9A-Fa-f]+,\s*(sub_[0-9A-Fa-f]{8})\s*\}")
    return set(rx.findall(MAP.read_text(encoding="utf-8", errors="ignore")))


def have_symbols():
    rx_def = re.compile(r"\bsub_[0-9A-Fa-f]{8}\b")
    have = set()
    for f in ROOT.glob("ppc_recomp.*.cpp"):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        have |= set(rx_def.findall(txt))
    if STUB.exists():
        have |= set(rx_def.findall(STUB.read_text(encoding="utf-8", errors="ignore")))
    return have


def emit_stubs(missing):
    lines = []
    lines.append('#include "ppc/ppc_context.h"')
    lines.append('#include <cstdio>')
    lines.append("")
    for name in sorted(missing):
        lines.append(f'extern "C" void {name}(PPCContext& __restrict, uint8_t*) ' + '{')
        lines.append(f'  std::fputs("[ppc][stub] {name}\\n", stderr);')
        lines.append('}')
    return "\n".join(lines) + "\n"


def main() -> int:
    need = need_symbols()
    have = have_symbols()
    miss = sorted(need - have)
    print(f"need={len(need)} have={len(have)} missing={len(miss)}")
    for n in miss[:20]:
        print("  ", n)
    STUB.write_text(emit_stubs(miss), encoding="utf-8")
    print(f"Wrote {STUB} with {len(miss)} stubs")
    return 0


if __name__ == "__main__":
    sys.exit(main())

