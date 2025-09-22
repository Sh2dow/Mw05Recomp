# find_pointer_indirect_writes.py
# Detect stores to targetEA performed *via a pointer* loaded from memory.
# Workflow:
#   1) Find all data cells == targetEA.
#   2) For each, find code that loads that address into a GPR (data xref from insn to the cell).
#   3) Track that GPR forward (mr/addi small), then flag st* disp(GPR) as writes to targetEA+disp.

import idaapi, ida_bytes, ida_funcs, ida_xref, ida_ua, idautils, idc, ida_kernwin

STORE_MNEMS = {
    "stw","stwu","stwx","stwux",
    "std","stdu","stdx","stdux",
    "sth","sthu","sthx","sthux",
    "stb","stbu","stbx","stbux",
}
LOAD_MNEMS = {"lwz","lwzu","ld","ldu"}  # extend if needed
ALIAS_MNEMS = {"mr"}                    # simple move
INC_MNEMS = {"addi","addic","addic."}   # allow base + small delta

def _mn(ea): 
    m = idc.print_insn_mnem(ea)
    return m.lower() if m else ""

def _is_code(ea):
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def _decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None

def _reg_idx(txt):
    if not txt or txt[0] != 'r': return None
    try: return int(txt[1:])
    except: return None

def _s16(v):
    v &= 0xFFFF
    return v - 0x10000 if (v & 0x8000) else v

def _insn_refs_data_ea(ea, data_ea):
    d = ida_xref.get_first_dref_from(ea)
    while d != idaapi.BADADDR:
        if d == data_ea:
            return True
        d = ida_xref.get_next_dref_from(ea, d)
    return False

def _iter_data_cells_equal_to(value):
    # Walk all segments; examine dwords that equal 'value'
    for seg_ea in idautils.Segments():
        s = idaapi.getseg(seg_ea)
        if not s: continue
        # Only scan non-code segments
        if s.type == idaapi.SEG_CODE:
            continue
        ea = s.start_ea
        while ea + 4 <= s.end_ea:
            try:
                dw = ida_bytes.get_dword(ea)
            except Exception:
                dw = None
            if dw == value:
                yield ea
            ea += 4

def _print(msg):
    ida_kernwin.msg(msg + "\n")

def find_pointer_indirect_writes(target_ea, fwd_window=64, allow_disp_max=0x200, tag="queue_head"):
    hits = []
    data_cells = list(_iter_data_cells_equal_to(target_ea))
    if not data_cells:
        _print(f"[ptr] No data cells equal to 0x{target_ea:08X} found. (Pointer var not present or packed?)")
        return hits
    _print(f"[ptr] Candidate pointer cells -> 0x{target_ea:08X}: {len(data_cells)}")

    for cell in data_cells:
        # Find code that references this cell (loads the pointer)
        xr = ida_xref.get_first_xref_to(cell)
        refs = []
        while xr:
            if xr.iscode:
                refs.append(xr.frm)
            xr = ida_xref.get_next_xref_to(cell, xr.frm)
        if not refs:
            continue

        for ea in sorted(set(refs)):
            if not _is_code(ea):
                continue
            insn = _decode(ea)
            if not insn:
                continue
            m = _mn(ea)
            if m not in LOAD_MNEMS and m not in ("lis","addis","ori","oris"):
                # Prefer actual loads; we tolerate half-const sequences, but pointer case is usually a load
                pass

            # Destination reg is op0 for PPC loads
            dest_txt = idc.print_operand(ea, 0)
            base_reg = _reg_idx(dest_txt)
            if base_reg is None:
                continue

            # Sanity: ensure the insn really references 'cell'
            if not _insn_refs_data_ea(ea, cell):
                continue

            # Track this base forward for a small window
            f = ida_funcs.get_func(ea)
            end = f.end_ea if f else idaapi.BADADDR

            aliases = {base_reg}  # track simple aliases of the base
            cur = ea
            steps = 0
            while steps < fwd_window and cur != idaapi.BADADDR and (end == idaapi.BADADDR or cur < end):
                cur = idc.next_head(cur, end)
                if cur == idaapi.BADADDR: break
                if not _is_code(cur): 
                    steps += 1
                    continue
                steps += 1
                m2 = _mn(cur)

                # Simple aliasing: mr rD, rS  (propagate base reg)
                if m2 in ALIAS_MNEMS:
                    d = _reg_idx(idc.print_operand(cur, 0))
                    s = _reg_idx(idc.print_operand(cur, 1))
                    if s in aliases and d is not None:
                        aliases.add(d)
                    continue

                # Base increment: addi rD, rS, simm16 when rS is base; include rD as new alias
                if m2 in INC_MNEMS:
                    d = _reg_idx(idc.print_operand(cur, 0))
                    s = _reg_idx(idc.print_operand(cur, 1))
                    if s in aliases and d is not None:
                        # You can check the size if you want: simm = _s16(idc.get_operand_value(cur, 2))
                        aliases.add(d)
                    continue

                # Check stores: st* ..., disp(rAlias)
                if m2 in STORE_MNEMS:
                    insn2 = _decode(cur)
                    if not insn2:
                        continue
                    base = disp = None
                    for op_idx in (1,2,0):
                        op = insn2.ops[op_idx]
                        if op.type == ida_ua.o_displ:
                            base = op.reg
                            disp = op.addr
                            break
                    if base is None:
                        continue
                    if base in aliases and 0 <= disp <= allow_disp_max:
                        # This is a write to targetEA+disp
                        idc.set_cmt(cur, f"[{tag}] store via ptr -> 0x{target_ea + disp:08X} (base=*{cell:08X})", 1)
                        idc.set_color(cur, idc.CIC_ITEM, 0x80FF00)
                        hits.append(cur)

    if hits:
        _print(f"[ptr] Found {len(hits)} indirect-pointer store(s) (within +0x{allow_disp_max:X}). Jumping to first …")
        idc.jumpto(hits[0])
    else:
        _print("[ptr] No indirect-pointer stores matched. Consider increasing window/disp, or enable memcpy/U128 logs.")
    return hits

# ---- interactive entry ----
def main():
    s = ida_kernwin.ask_str("0x82A384D4", 0, "Target EA (hex)")
    if not s: return
    try:
        tgt = int(s, 16)
    except Exception:
        ida_kernwin.msg("[ptr] Invalid hex.\n"); return
    w = ida_kernwin.ask_str("64", 0, "Forward window (instructions)")
    try:
        win = int(w) if w else 64
    except Exception:
        win = 64
    disp = ida_kernwin.ask_str("0x200", 0, "Max displacement from target (hex)")
    try:
        md = int(disp, 16) if disp else 0x200
    except Exception:
        md = 0x200
    find_pointer_indirect_writes(tgt, fwd_window=win, allow_disp_max=md, tag="queue_head")

if __name__ == "__main__":
    main()
