# scan_dispatch_callees_for_store.py
# Scan dispatch tables for a callee that stores to a specific global EA.

import idaapi, ida_bytes, ida_funcs, ida_kernwin, ida_name, ida_xref, idautils, idc

STORE_MNEMS = {
    "stw","stwu","stwx","stwux",
    "std","stdu","stdx","stdux",
    "sth","sthu","sthx","sthux",
    "stb","stbu","stbx","stbux",
}
SET_HI = {"lis","addis"}
OR_LO  = {"ori","oris"}
ADD_IMM= {"addi","addic","addic."}
MOVE   = {"mr"}
ADD    = {"add"}

def _mn(ea): 
    m = idc.print_insn_mnem(ea)
    return m.lower() if m else ""

def _decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None

def _is_code(ea): 
    return ida_bytes.is_code(ida_bytes.get_full_flags(ea))

def _u16(v): return v & 0xFFFF
def _s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v

def _mem_displ_info(insn, op_idx):
    op = insn.ops[op_idx]
    if op.type != ida_ua.o_displ:
        return (None, None)
    return (op.reg, op.addr)  # base reg index, displacement (signed already)

def _reg_idx(text):
    if not text or text[0] != 'r': return None
    try: return int(text[1:])
    except: return None

def _scan_func_for_target(func, target_ea, tag_name, color=0x00C0FF):
    consts = {i: (False, 0) for i in range(32)}  # reg -> (known, value)
    hits = []

    ea = func.start_ea
    while ea < func.end_ea:
        if not _is_code(ea):
            ea = idc.next_head(ea, func.end_ea); continue

        insn = _decode(ea)
        if not insn:
            ea = idc.next_head(ea, func.end_ea); continue

        m = _mn(ea)

        # --- check store
        if m in STORE_MNEMS:
            for op_idx in (1, 2, 0):  # mem operand could be in different slots
                base, disp = _mem_displ_info(insn, op_idx)
                if base is None:
                    continue
                if base == 1:  # r1 = stack; ignore local stores
                    break
                known, baseval = consts.get(base, (False, 0))
                if known:
                    ea_abs = (baseval + disp) & 0xFFFFFFFF
                    if ea_abs == target_ea:
                        idc.set_cmt(ea, f"[{tag_name}] store -> 0x{target_ea:X}", 1)
                        idc.set_color(ea, idc.CIC_ITEM, color)
                        hits.append(ea)
                break  # only one mem operand matters

        # --- update constant map
        D = idc.print_operand(ea, 0); d = _reg_idx(D)
        S = idc.print_operand(ea, 1); s = _reg_idx(S)
        A = idc.print_operand(ea, 1); a = _reg_idx(A)
        B = idc.print_operand(ea, 2); b = _reg_idx(B)

        if m in SET_HI:
            if d is not None:
                if m == "lis":
                    imm = _u16(idc.get_operand_value(ea, 1))
                    consts[d] = (True, (imm << 16) & 0xFFFFFFFF)
                else:  # addis rD, rA, imm
                    a = _reg_idx(idc.print_operand(ea, 1))
                    imm = _u16(idc.get_operand_value(ea, 2))
                    if a == 0:  # keep only when based on r0
                        consts[d] = (True, (imm << 16) & 0xFFFFFFFF)
                    else:
                        consts[d] = (False, 0)

        elif m in OR_LO:
            if d is not None and s is not None:
                known, val = consts.get(s, (False, 0))
                imm = _u16(idc.get_operand_value(ea, 2))
                if known:
                    if m == "oris":
                        val |= (imm << 16)
                    else:
                        val |= imm
                    consts[d] = (True, val & 0xFFFFFFFF)
                else:
                    consts[d] = (False, 0)

        elif m in ADD_IMM:
            if d is not None and a is not None:
                known, val = consts.get(a, (False, 0))
                simm = _s16(idc.get_operand_value(ea, 2))
                if known:
                    consts[d] = (True, (val + simm) & 0xFFFFFFFF)
                else:
                    consts[d] = (False, 0)

        elif m in MOVE:
            if d is not None and s is not None:
                consts[d] = consts.get(s, (False, 0))

        elif m in ADD:
            if d is not None and a is not None and b is not None:
                ka, va = consts.get(a, (False, 0))
                kb, vb = consts.get(b, (False, 0))
                consts[d] = ((True, (va + vb) & 0xFFFFFFFF) if (ka and kb) else (False, 0))

        ea = idc.next_head(ea, func.end_ea)

    return hits

def dump_table(start_ea, end_ea):
    items = []
    for p in range(start_ea, end_ea, 4):
        tgt = ida_bytes.get_dword(p)
        if tgt not in (0, 0xFFFFFFFF):
            items.append((p, tgt))
    return items

def ea_by_name(sym):
    ea = ida_name.get_name_ea(idaapi.BADADDR, sym)
    if ea == idaapi.BADADDR:
        raise RuntimeError(f"symbol not found: {sym}")
    return ea

def scan_tables_for_store(target_ea, tables, tag_name="queue_head"):
    ida_kernwin.msg(f"[scan] target EA = 0x{target_ea:08X}\n")
    all_items = []
    for (start_ea, end_ea, label) in tables:
        ents = dump_table(start_ea, end_ea)
        ida_kernwin.msg(f"[scan] table {label}: {len(ents)} entries\n")
        all_items.extend((label, p, tgt) for (p, tgt) in ents)

    writers = []
    for label, ptr_ea, tgt in all_items:
        f = ida_funcs.get_func(tgt)
        if not f:
            continue
        hits = _scan_func_for_target(f, target_ea, tag_name)
        if hits:
            name = ida_funcs.get_func_name(f.start_ea) or f"sub_{f.start_ea:X}"
            ida_kernwin.msg(f"[scan] HIT in {name} (0x{f.start_ea:X}) — {len(hits)} store(s)\n")
            # annotate the pointer entry with a dref (optional, best-effort)
            try:
                ida_xref.add_dref(ptr_ea, tgt, ida_xref.dr_O | ida_xref.XREF_USER)
            except Exception:
                pass
            writers.append((f.start_ea, hits))

    if not writers:
        ida_kernwin.msg("[scan] No writers found in the provided tables.\n")
        return []

    # Jump to the first hit
    idc.jumpto(writers[0][1][0])
    ida_kernwin.msg(f"[scan] Total writer functions: {len(writers)} (jumped to first hit)\n")
    return writers

# === Configure & run ===
def main():
    # Your two tables from the dispatcher:
    t1 = (ea_by_name("unk_828DF0FC"), ea_by_name("unk_828DF108"), "init_cb_small")
    t2 = (ea_by_name("unk_828D0010"), ea_by_name("unk_828DF0F8"), "init_cb_big")

    # Ask for the target EA (default: dword_82A384D4)
    s = ida_kernwin.ask_str("0x82A384D4", 0, "Target EA (hex)")
    if not s:
        return
    try:
        target = int(s, 16)
    except Exception:
        ida_kernwin.msg("[scan] Invalid hex value.\n"); return

    scan_tables_for_store(target, [t1, t2], tag_name="queue_head")

if __name__ == "__main__":
    main()
