import ida_funcs
import ida_bytes
import ida_ua
import idautils
import idc

def list_call_targets(func_ea):
    f = ida_funcs.get_func(func_ea)
    if not f:
        print(f"[!] No function at {func_ea:x}")
        return
    print(f"[list_call_targets] Function {func_ea:x}-{f.end_ea:x}")

    for ea in idautils.FuncItems(func_ea):
        if ida_bytes.is_code(ida_bytes.get_full_flags(ea)):
            mnem = idc.print_insn_mnem(ea)
            if mnem in ("bl", "bctrl"):
                opnd = idc.print_operand(ea, 0)
                print(f"  {ea:x}: {mnem} {opnd}")

    print("[done]")

list_call_targets(0x8262FC50)
