# usage: python find_ea_writers_v2.py path/to/HOST.log --ea 0x82A384D4 --context 8 --include-memcpy --diagnose --loose
import re
import argparse

HEX32 = r"[0-9A-Fa-f]{8}"

# Flexible patterns (case-insensitive)
RE_STORE = re.compile(rf"HOST\.Store(?:8|32|64|128)BE_W(?:\.called)?\s+ea=(?P<ea>{HEX32})", re.IGNORECASE)
RE_ANYEA = re.compile(rf"\bea=(?P<ea>{HEX32})\b", re.IGNORECASE)  # loose fallback
RE_MEMCPY = re.compile(rf"\b(?:memcpy|memmove)\b.*\bdst=(?P<dst>{HEX32})", re.IGNORECASE)
RE_WATCH_ANY = re.compile(rf"HOST\.watch\.any.*?\bea=(?P<ea>{HEX32})\s+lr=(?P<lr>[0-9A-Fa-f]+)", re.IGNORECASE)
RE_WAIT_W4 = re.compile(rf"HOST\.sub_826346A8\.block.*?ea=(?P<block>{HEX32}).*?w4=(?P<w4>{HEX32})", re.IGNORECASE)
RE_LR = re.compile(r"\blr=0x?([0-9A-Fa-f]+)")


def scan_file(path, target_ea, context, include_memcpy, loose, diagnose):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if diagnose:
        # Count store lines for sanity
        store_lines = [i for i, ln in enumerate(lines) if RE_STORE.search(ln)]
        print(f"[diagnose] STORE lines found: {len(store_lines)}")
        for idx in store_lines[:5]:
            print(f"[diagnose]   sample #{idx}: {lines[idx].rstrip()}")
        print()

    target_ea = int(target_ea, 16)
    hits = []

    def record(kind, idx):
        # find nearest preceding LR mention (within 200 lines)
        nearest_lr = "unknown"
        for j in range(idx, max(-1, idx-200), -1):
            m = RE_LR.search(lines[j])
            if m:
                nearest_lr = m.group(1).upper()
                break
        hits.append((kind, idx, nearest_lr))

    # 1) Direct Store* hits
    for i, ln in enumerate(lines):
        m = RE_STORE.search(ln)
        if m and int(m.group("ea"), 16) == target_ea:
            record("STORE", i)

    # 2) memcpy/memmove
    if include_memcpy:
        for i, ln in enumerate(lines):
            m = RE_MEMCPY.search(ln)
            if m and int(m.group("dst"), 16) == target_ea:
                record("MEMCPY", i)

    # 3) watch.any lines (for the *watch slot*, not the target global)
    #    These help you grab an LR to jump into IDA.
    watch_any = []
    for i, ln in enumerate(lines):
        m = RE_WATCH_ANY.search(ln)
        if m:
            watch_any.append((i, m.group("ea"), m.group("lr"))

    # 4) waiter observe lines (w4=0A000000) to provide context even if no store logged
    waiter_obs = []
    for i, ln in enumerate(lines):
        m = RE_WAIT_W4.search(ln)
        if m and m.group("w4").upper() == "0A000000":
            waiter_obs.append((i, m.group("block")))

    # 5) Loose fallback: anything that says "ea=XXXXXXXX" equal to target
    if loose and not hits:
        for i, ln in enumerate(lines):
            m = RE_ANYEA.search(ln)
            if m and int(m.group("ea"), 16) == target_ea:
                record("EA_MATCH", i)

    # Output
    if not hits:
        print(f"[info] No direct Store*/memcpy hits to EA 0x{target_ea:08X}.")
        if watch_any:
            print(f"[info] Found {len(watch_any)} HOST.watch.any lines (use their LR in IDA):")
            for i, ea, lr in watch_any[:10]:
                print(f"  line {i}: ea={ea} lr={lr}")
        if waiter_obs:
            print(f"[info] Found {len(waiter_obs)} waiter observe lines with w4=0A000000 (synth wake sites).")
            for i, blk in waiter_obs[:10]:
                print(f"  line {i}: block={blk}  (watchEA would be block+0x10)")
        print("[hint] If you expected Store64 lines but see none, ensure your build prints 'HOST.Store64BE_W.called ...' or enable the U8/U128/memcpy watchers.")
        return

    print(f"[ok] Found {len(hits)} hit(s) to 0x{target_ea:08X}\n")
    for kind, idx, lr in hits:
        print("="*90)
        print(f"{kind} at line {idx}  (nearest LR={lr})")
        start = max(0, idx-context)
        end = min(len(lines), idx+context+1)
        for k in range(start, end):
            mark = ">>" if k == idx else "  "
            print(f"{mark} {k:06d}: {lines[k].rstrip()}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--ea", required=True, help="Target EA hex, e.g. 0x82A384D4")
    ap.add_argument("--context", type=int, default=8)
    ap.add_argument("--include-memcpy", action="store_true")
    ap.add_argument("--loose", action="store_true", help="Fallback to any 'ea=XXXX' mentions")
    ap.add_argument("--diagnose", action="store_true", help="Show counts and samples of STORE lines")
    args = ap.parse_args()

    scan_file(args.logfile, args.ea, args.context, args.include_memcpy, args.loose, args.diagnose)
