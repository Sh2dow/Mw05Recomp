import idaapi, ida_funcs, ida_bytes, ida_ua, ida_segment, idautils, idc

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
    return (op.reg, op.addr)  # base reg index, displacement

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
                if base == 1:  # r1 = stack, ignore (not a global)
                    break
                known, baseval = consts.get(base, (False, 0))
                if known:
                    ea_abs = (baseval + disp) & 0xFFFFFFFF
                    if ea_abs == target_ea:
                        idc.set_cmt(ea, f"[{tag_name}] store -> 0x{target_ea:X}", 1)
                        idc.set_color(ea, idc.CIC_ITEM, color)
                        hits.append(ea)
                break  # only one mem operand matters

        # --- update consts
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
                    if a == 0:  # only keep if base is r0
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
                consts[d] = ((True, (val + simm) & 0xFFFFFFFF) if known else (False, 0))

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

def find_stores_to_ea(target_ea, tag_name="queue_head", rename_global=True):
    all_hits = []
    for fva in idautils.Functions():
        f = ida_funcs.get_func(fva)
        if not f: 
            continue
        hits = _scan_func_for_target(f, target_ea, tag_name)
        if hits:
            all_hits.append((fva, hits))

    if rename_global:
        try:
            idc.set_name(target_ea, tag_name, idc.SN_CHECK)
        except Exception:
            pass

    # Report
    if not all_hits:
        print(f"[find_stores_to_ea] No stores resolved to 0x{target_ea:X}.")
        return []

    print(f"[find_stores_to_ea] Found {sum(len(h) for _,h in all_hits)} store(s) across {len(all_hits)} function(s):")
    for fva, hits in all_hits:
        fname = ida_funcs.get_func_name(fva) or f"sub_{fva:X}"
        print(f"  - {fname}:")
        for ea in hits:
            print(f"      * 0x{ea:X}")
    idc.jumpto(all_hits[0][1][0])
    return all_hits

# Convenience wrapper if you still want to start from LR:
def tag_queue_head(lr_ea, target_ea, name="queue_head"):
    f = ida_funcs.get_func(lr_ea)
    if not f:
        print(f"[tag_queue_head] No function at 0x{lr_ea:X}")
        return []
    hits = _scan_func_for_target(f, target_ea, name)
    if hits:
        try: idc.set_name(target_ea, name, idc.SN_CHECK)
        except: pass
        print(f"[tag_queue_head] Tagged {len(hits)} store(s) in {ida_funcs.get_func_name(f.start_ea)}")
        idc.jumpto(hits[0]); 
        return [(f.start_ea, hits)]
    print("[tag_queue_head] No store in that function; scanning whole DB…")
    return find_stores_to_ea(target_ea, name)

def main():
    lr = _ask_hex("Enter LR address (inside producer function)", 0x8262FC50)
    if lr is None:
        return
    tgt = _ask_hex("Enter target global EA (e.g., dword_82A384D4)", 0x82A384D4)
    if tgt is None:
        return
    name = ida_kernwin.ask_str("queue_head", 0, "Global name to assign (optional)")
    if not name:
        name = "queue_head"
    tag_queue_head(lr, tgt, name)

if __name__ == "__main__":
    main()
