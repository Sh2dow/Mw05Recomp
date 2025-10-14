# ida_api_server.py — HTTP JSON API for IDA (main-thread safe)

import json
import threading
import binascii
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import idaapi
import idc
import ida_funcs
import ida_bytes
import idautils
import ida_kernwin

# Try ThreadingHTTPServer; fall back to HTTPServer if missing
try:
    from http.server import ThreadingHTTPServer as _ThreadingHTTPServer
except ImportError:
    _ThreadingHTTPServer = None

# Hex-Rays availability
HAS_HEXRAYS = False
try:
    import ida_hexrays
    if ida_hexrays.init_hexrays_plugin():
        HAS_HEXRAYS = True
except Exception:
    HAS_HEXRAYS = False


# ---------- helpers ----------

def run_in_mainthread(fn, mode=ida_kernwin.MFF_READ):
    """
    Execute 'fn' on IDA's main thread and return its result.
    mode: MFF_READ is safe for queries; use MFF_FAST for quick UI ops.
    """
    box = {"res": None, "err": None}

    def _thunk():
        try:
            box["res"] = fn()
        except Exception as e:
            box["err"] = e
        return 1

    ida_kernwin.execute_sync(_thunk, mode)
    if box["err"] is not None:
        raise box["err"]
    return box["res"]


def parse_ea_param(qs, key="ea"):
    v = qs.get(key)
    if not v:
        raise ValueError("missing ea")
    s = v[0].strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return int(s, 16)


def hex_ea(ea):
    return "0x{:X}".format(ea)


def get_bytes_hex(ea, size=32):
    b = ida_bytes.get_bytes(ea, int(size) if size else 32) or b""
    return binascii.hexlify(b).decode()


def get_disasm_block(start_ea, end_ea, max_insn=200):
    lines = []
    ea = start_ea
    count = 0
    while ea != idaapi.BADADDR and ea < end_ea and count < max_insn:
        dis = idc.GetDisasm(ea)
        if dis:
            lines.append({"ea": hex_ea(ea), "text": dis})
            count += 1
        ea = idc.next_head(ea, end_ea)
    return lines


def try_decompile_func(func):
    if not HAS_HEXRAYS or not func:
        return None
    try:
        cfunc = ida_hexrays.decompile(func)
        if cfunc:
            return str(cfunc)
    except Exception:
        return None
    return None


def gather_xrefs_from(ea):
    res = []
    for xr in idautils.XrefsFrom(ea, 0):
        res.append({"from": hex_ea(xr.frm), "to": hex_ea(xr.to), "type": xr.type})
    return res


def gather_xrefs_to(ea):
    res = []
    for xr in idautils.XrefsTo(ea, 0):
        res.append({"from": hex_ea(xr.frm), "to": hex_ea(xr.to), "type": xr.type})
    return res


def callers_of(func):
    callers = set()
    if not func:
        return []
    for r in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsTo(r, 0):
            f = ida_funcs.get_func(xr.frm)
            if f:
                callers.add(f.start_ea)
    return [hex_ea(x) for x in sorted(callers)]


def callees_of(func):
    callees = set()
    if not func:
        return []
    for r in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsFrom(r, 0):
            f = ida_funcs.get_func(xr.to)
            if f:
                callees.add(f.start_ea)
    return [hex_ea(x) for x in sorted(callees)]


def get_function_context(ea):
    head = idc.get_item_head(ea)
    if head != idaapi.BADADDR:
        ea = head

    func = ida_funcs.get_func(ea)
    func_name = ida_funcs.get_func_name(ea) if func else None

    if func:
        start = func.start_ea
        end = func.end_ea
    else:
        start = max(0, ea)
        end = ea + 0x100

    bytes_at_ea = get_bytes_hex(ea, 64)
    disasm = get_disasm_block(start, end, max_insn=1000 if func else 128)
    pseudo = try_decompile_func(func)
    xrefs_from = gather_xrefs_from(ea)
    xrefs_to = gather_xrefs_to(ea)
    callers = callers_of(func) if func else []
    callees = callees_of(func) if func else []
    func_cmt = idc.get_func_cmt(start, False) if func else None

    instr_comments = []
    for item in idautils.Heads(start, end):
        c = idc.get_cmt(item, False) or idc.get_cmt(item, True)
        if c:
            instr_comments.append({"ea": hex_ea(item), "comment": c})

    return {
        "input_ea": hex_ea(ea),
        "ea": hex_ea(ea),
        "in_function": func is not None,
        "function": {
            "name": func_name,
            "start_ea": hex_ea(start),
            "end_ea": hex_ea(end),
        } if func else None,
        "bytes_at_ea": bytes_at_ea,
        "disasm": disasm,
        "pseudocode": pseudo,
        "xrefs_from": xrefs_from,
        "xrefs_to": xrefs_to,
        "callers": callers,
        "callees": callees,
        "function_comment": func_cmt,
        "instr_comments": instr_comments,
    }

# --- count-based disasm helper ---
def get_disasm_from(ea, count=50):
    """Disassemble 'count' instructions starting at/near EA."""
    # normalize to item head
    try:
        head = idc.get_item_head(ea)
    except AttributeError:
        head = idc.GetItemHead(ea)
    if head != idaapi.BADADDR:
        ea = head

    # pick a safe upper bound (end of segment if possible, else process max EA)
    seg = idaapi.getseg(ea)
    if seg:
        max_ea = seg.end_ea
    else:
        max_ea = idaapi.get_inf_structure().max_ea

    lines = []
    i = 0
    cur = ea
    while cur != idaapi.BADADDR and cur < max_ea and i < int(count):
        txt = idc.GetDisasm(cur)
        if txt:
            lines.append({"ea": hex_ea(cur), "text": txt})
            i += 1
        # advance to next item
        try:
            cur = idc.next_head(cur, max_ea)   # IDA 7+
        except AttributeError:
            cur = idc.NextHead(cur, max_ea)    # legacy
    return {"start_ea": hex_ea(ea), "count": len(lines), "disasm": lines}

# ---------- HTTP handler ----------

class IDARequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, ensure_ascii=False)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body.encode("utf-8"))))
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self):
        try:
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            path = u.path

            if path == "/func":
                ea = parse_ea_param(qs, "ea")

                def _job():
                    idaapi.auto_wait()
                    return get_function_context(ea)

                data = run_in_mainthread(_job, ida_kernwin.MFF_READ)
                self._send_json(data)
                return

            if path == "/decompile":
                ea = parse_ea_param(qs, "ea")

                def _job():
                    idaapi.auto_wait()
                    f = ida_funcs.get_func(ea)
                    if not f or not HAS_HEXRAYS:
                        return {"error": "no-function-or-no-hexrays"}
                    return {"ea": hex_ea(ea), "pseudocode": try_decompile_func(f)}

                data = run_in_mainthread(_job, ida_kernwin.MFF_READ)
                status = 200 if "pseudocode" in data else 404
                self._send_json(data, status=status)
                return

            if path == "/bytes":
                ea = parse_ea_param(qs, "ea")
                size = int(qs.get("size", ["32"])[0])

                def _job():
                    return {"ea": hex_ea(ea), "size": size, "bytes_hex": get_bytes_hex(ea, size)}

                data = run_in_mainthread(_job, ida_kernwin.MFF_READ)
                self._send_json(data)
                return

            if path == "/xrefs":
                ea = parse_ea_param(qs, "ea")
                direction = qs.get("dir", ["both"])[0]

                def _job():
                    if direction == "from":
                        return {"ea": hex_ea(ea), "xrefs_from": gather_xrefs_from(ea)}
                    elif direction == "to":
                        return {"ea": hex_ea(ea), "xrefs_to": gather_xrefs_to(ea)}
                    else:
                        return {
                            "ea": hex_ea(ea),
                            "xrefs_from": gather_xrefs_from(ea),
                            "xrefs_to": gather_xrefs_to(ea),
                        }

                data = run_in_mainthread(_job, ida_kernwin.MFF_READ)
                self._send_json(data)
                return
		
            if path == "/disasm":
                ea = parse_ea_param(qs, "ea")
                count = int(qs.get("count", ["50"])[0])

                def _job():
                    idaapi.auto_wait()
                    return get_disasm_from(ea, count)

                data = run_in_mainthread(_job, ida_kernwin.MFF_READ)
                self._send_json(data)
                return

            self.send_error(404, "unknown endpoint")

        except Exception as e:
            # Return the actual error message so it's easier to debug from curl
            self._send_json({"error": str(e)}, status=500)


# ---------- server bootstrap ----------

SERVER = None

def start_server(host="127.0.0.1", port=5050, background=True):
    global SERVER
    ServerClass = _ThreadingHTTPServer if _ThreadingHTTPServer else HTTPServer
    SERVER = ServerClass((host, port), IDARequestHandler)
    idaapi.msg(f"IDA API server listening on {host}:{port}\n")
    if background:
        t = threading.Thread(target=SERVER.serve_forever, daemon=True)
        t.start()
        idaapi.msg("Server started in background thread.\n")
    else:
        SERVER.serve_forever()

def stop_server():
    global SERVER
    if SERVER:
        idaapi.msg("Stopping IDA API server...\n")
        SERVER.shutdown()
        SERVER.server_close()
        SERVER = None
        idaapi.msg("Server stopped.\n")

if __name__ == "__main__":
    # GUI → background=True; Headless → either is fine.
    start_server(background=True)
