# find_writes_to_ea_smart.py
# Find PPC stores to a specific EA, including indirect pointer writes.
#
# Matches:
#   A) st* ..., disp(r0)                       -> EA == disp
#   B) st* ..., disp(rX) with const base       -> (base + disp) == targetEA
#   C) st* ..., disp(rX) where base == targetEA
#      (indirect pointer write; disp=0 -> exact, disp>0 -> targetEA+disp)
#
# Backtracks up to N instructions to resolve base constants:
#   lis/addis, ori/oris, addi, mr, add  (const+const)

import idaapi, ida_funcs, ida_bytes, ida_ua, idautils, idc, ida_kernwin

STORE_MNEMS = {
    "stw","stwu","stwx","stwux",
    "std","stdu","stdx","stdux",
    "sth","sthu","sthx","sthux",
    "stb","stbu","stbx","stbux",
}

def _mn(ea):
    m = idc.print_insn_mnem(ea)
    return m.lower() if m else ""

def _decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None

def _is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def _mem_displ(insn, op_idx):
    op = insn.ops[op_idx]
    if op.type != ida_ua.o_displ:
        return (None, None)
    # For PPC, op.reg is base GPR, op.addr is signed displacement
    return (op.reg, op.addr)

def _reg_idx(txt):
    if not txt or txt[0] != 'r': return None
    try: return int(txt[1:])
    except: return None

def _u16(v): return v & 0xFFFF
def _s16(v):
    v &= 0xFFFF
    return v - 0x10000 if (v & 0x8000) else v

def _try_backtrack_const_base(store_ea, base_reg, max_steps=12):
    """
    Walk backwards up to max_steps to resolve a constant absolute value for base_reg.
    Handles: lis/addis, ori/oris, addi, mr, add (const+const).
    Returns (known, value).
    """
    def _resolve_chain(start_ea, want_reg, budget, ops):
        k, v = _try_backtrack_const_base(start_ea, want_reg, max_steps=budget)
        if not k:
            return False, 0
        for kind, imm, hi in ops:  # re-apply ops in forward sense
            if kind == "or":
                v |= (imm << 16) if hi else imm
                v &= 0xFFFFFFFF
            elif kind == "add":
                v = (v + imm) & 0xFFFFFFFF
        return True, v

    known = False
    val = 0
    want = base_reg
    ea = store_ea
    steps = 0

    while steps < max_steps and ea != idaapi.BADADDR:
        ea = idc.prev_head(ea)
        if ea == idaapi.BADADDR or not _is_code(ea):
            break
        steps += 1
        m = _mn(ea)

        D = idc.print_operand(ea, 0); d = _reg_idx(D)
        S = idc.print_operand(ea, 1); s = _reg_idx(S)
        A = idc.print_operand(ea, 1); a = _reg_idx(A)
        B = idc.print_operand(ea, 2); b = _reg_idx(B)

        if d != want:
            continue

        if m == "lis":
            imm = _u16(idc.get_operand_value(ea, 1))
            return True, (imm << 16) & 0xFFFFFFFF
        elif m == "addis":
            a = _reg_idx(idc.print_operand(ea, 1))
            imm = _u16(idc.get_operand_value(ea, 2))
            if a == 0:
                return True, (imm << 16) & 0xFFFFFFFF
            return False, 0
        elif m in ("ori","oris"):
            imm = _u16(idc.get_operand_value(ea, 2))
            # resolve source then OR
            return _resolve_chain(ea, s, max_steps - steps, [("or", imm, (m=="oris"))])
        elif m in ("addi","addic","addic."):
            simm = _s16(idc.get_operand_value(ea, 2))
            return _resolve_chain(ea, a, max_steps - steps, [("add", simm, False)])
        elif m == "mr":
            want = s
            continue
        elif m == "add":
            if a is None or b is None:
                return False, 0
            k1, v1 = _try_backtrack_const_base(ea, a, max_steps - steps)
            k2, v2 = _try_backtrack_const_base(ea, b, max_steps - steps)
            if k1 and k2:
                return True, (v1 + v2) & 0xFFFFFFFF
            return False, 0
        else:
            return False, 0

    return known, val

def find_writes_to_ea(target_ea, backtrack=12, tag="queue_head", indirect_disp_max=0x40):
    """
    Scan all functions and tag stores that hit target_ea directly or via an indirect pointer base.
    - indirect_disp_max: allow small positive/zero disp for pointer writes to targetEA+disp (default 0x40).
    """
    hits = []

    for fva in idautils.Functions():
        f = ida_funcs.get_func(fva)
        if not f:
            continue

        ea = f.start_ea
        while ea < f.end_ea:
            if not _is_code(ea):
                ea = idc.next_head(ea, f.end_ea); continue

            insn = _decode(ea)
            if not insn:
                ea = idc.next_head(ea, f.end_ea); continue

            m = _mn(ea)
            if m not in STORE_MNEMS:
                ea = idc.next_head(ea, f.end_ea); continue

            # find displacement operand
            base = disp = None
            for op_idx in (1, 2, 0):
                base, disp = _mem_displ(insn, op_idx)
                if base is not None:
                    break
            if base is None:
                ea = idc.next_head(ea, f.end_ea); continue

            # A) absolute via r0
            if base == 0:
                ea_abs = disp & 0xFFFFFFFF
                if ea_abs == target_ea:
                    idc.set_cmt(ea, f"[{tag}] store -> 0x{target_ea:X} (abs r0)", 1)
                    idc.set_color(ea, idc.CIC_ITEM, 0x00C0FF)
                    hits.append(ea)
                ea = idc.next_head(ea, f.end_ea); continue

            # B/C) backtrack base constant
            known, baseval = _try_backtrack_const_base(ea, base, max_steps=backtrack)
            if not known:
                ea = idc.next_head(ea, f.end_ea); continue

            # B) base + disp equals target
            ea_abs = (baseval + disp) & 0xFFFFFFFF
            if ea_abs == target_ea:
                idc.set_cmt(ea, f"[{tag}] store -> 0x{target_ea:X}", 1)
                idc.set_color(ea, idc.CIC_ITEM, 0x00C0FF)
                hits.append(ea)
                ea = idc.next_head(ea, f.end_ea); continue

            # C) indirect pointer write: base itself equals targetEA, small disp allowed
            if baseval == target_ea and 0 <= disp <= indirect_disp_max:
                note = "indirect ptr"
                if disp != 0:
                    note += f" (+{disp:#x})"
                idc.set_cmt(ea, f"[{tag}] store -> 0x{target_ea:X} {note}", 1)
                idc.set_color(ea, idc.CIC_ITEM, 0x80FF00)
                hits.append(ea)

            ea = idc.next_head(ea, f.end_ea)

    if hits:
        print(f"[find_writes_to_ea] Found {len(hits)} store(s) to 0x{target_ea:08X}")
        idc.jumpto(hits[0])
    else:
        print(f"[find_writes_to_ea] No stores found to 0x{target_ea:08X}.\n"
              f"  • If the writer uses memcpy/128-bit stores, enable/log those paths and use the LR.\n"
              f"  • You can increase backtrack window or indirect_disp_max if needed.")
    return hits

# --- interactive entrypoint (works on IDA 7.5–9) ---
def main():
    s = ida_kernwin.ask_str("0x82A384D4", 0, "Target EA (hex)")
    if not s: return
    try:
        tgt = int(s, 16)
    except Exception:
        print("[find_writes_to_ea] Invalid hex."); return

    bt_s = ida_kernwin.ask_str("12", 0, "Backtrack window (instructions)")
    try:
        bt = int(bt_s)
    except Exception:
        bt = 12

    disp_s = ida_kernwin.ask_str("0x40", 0, "Max indirect displacement (hex, for targetEA+disp)")
    try:
        indirect_max = int(disp_s, 16) if disp_s else 0x40
    except Exception:
        indirect_max = 0x40

    find_writes_to_ea(tgt, backtrack=bt, tag="queue_head", indirect_disp_max=indirect_max)

if __name__ == "__main__":
    main()
