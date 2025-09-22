# ida_dump_dispatch_tables.py
import idaapi, ida_name, ida_bytes, ida_kernwin, ida_funcs, ida_xref

def ea(sym):
    ea = ida_name.get_name_ea(idaapi.BADADDR, sym)
    if ea == idaapi.BADADDR:
        raise RuntimeError(f"symbol not found: {sym}")
    return ea

def read_u32(ea_):
    return ida_bytes.get_dword(ea_)

def in_text(ea_):
    f = ida_funcs.get_func(ea_)
    return f is not None

def dump_table(start_ea, end_ea, base_name="dispatch_cb"):
    import idaapi, ida_name, ida_bytes, ida_kernwin, ida_funcs, ida_xref, idc

    def try_make_offset(ea, opnum, target):
        # Try multiple IDA APIs, tolerate absence
        ok = False
        try:
            # Newer IDA: op_plain_offset(ea, n, target)
            ok = ida_bytes.op_plain_offset(ea, opnum, target)
        except Exception:
            pass
        if not ok:
            try:
                # Older IDA idc wrapper
                ok = idc.op_plain_offset(ea, opnum, target)
            except Exception:
                pass
        return ok

    def read_u32(ea_):
        return ida_bytes.get_dword(ea_)

    def is_code(ea_):
        return ida_funcs.get_func(ea_) is not None

    items = []
    idx = 0
    for p in range(start_ea, end_ea, 4):
        tgt = read_u32(p)
        if tgt not in (0, 0xFFFFFFFF):
            items.append((idx, p, tgt))
        idx += 1

    if not items:
        ida_kernwin.msg(f"[dispatch] no entries in {start_ea:08X}-{end_ea:08X}\n")
        return []

    ida_kernwin.msg(f"[dispatch] entries in {start_ea:08X}-{end_ea:08X}: {len(items)}\n")
    out = []
    for i, ptr_ea, tgt in items:
        # Best-effort: show it as an offset and create a data xref
        try_make_offset(ptr_ea, 0, tgt)
        ida_xref.add_dref(ptr_ea, tgt, ida_xref.XREF_USER | ida_xref.dr_O)

        # Name/print target
        name = ida_funcs.get_func_name(tgt)
        if not name and is_code(tgt):
            name = f"{base_name}_{i:04d}"
            ida_name.set_name(tgt, name, ida_name.SN_CHECK)
        if not name:
            name = f"sub_{tgt:08X}" if is_code(tgt) else f"data_{tgt:08X}"

        ida_kernwin.msg(f"  [{i:04d}] *{ptr_ea:08X} -> {name} (0x{tgt:08X})\n")
        out.append((i, ptr_ea, tgt, name))

    if out:
        ida_kernwin.msg(f"[dispatch] jump to first: {out[0][3]} @ 0x{out[0][2]:08X}\n")
        idaapi.jumpto(out[0][2])
    return out

def dump_known_tables():
    # Tables visible in your listing
    t1 = dump_table(ea("unk_828DF0FC"), ea("unk_828DF108"), base_name="init_cb_small")
    t2 = dump_table(ea("unk_828D0010"), ea("unk_828DF0F8"), base_name="init_cb_big")
    return t1, t2

if __name__ == "__main__":
    try:
        dump_known_tables()
    except Exception as e:
        ida_kernwin.msg(f"[dispatch] error: {e}\n")
