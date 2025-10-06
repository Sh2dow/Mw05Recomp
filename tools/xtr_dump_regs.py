#!/usr/bin/env python3
import io
import os
import struct
import sys

TRACE_COMMAND_TYPE = {
    0: 'PrimaryBufferStart',
    1: 'PrimaryBufferEnd',
    2: 'IndirectBufferStart',
    3: 'IndirectBufferEnd',
    4: 'PacketStart',
    5: 'PacketEnd',
    6: 'MemoryRead',
    7: 'MemoryWrite',
    8: 'EdramSnapshot',
    9: 'Event',
    10: 'Registers',
    11: 'GammaRamp',
}

MEM_ENCODING_NONE = 0
MEM_ENCODING_SNAPPY = 1

# Minimal subset of registers of interest (Xenos dword indices)
REG_NAME = {
    0x2000: 'RB_SURFACE_INFO',
    0x2001: 'RB_COLOR_INFO',
    0x2002: 'RB_DEPTH_INFO',
    0x2104: 'RB_COLOR_MASK',
    0x2200: 'RB_DEPTHCONTROL',
    0x200E: 'PA_SC_SCREEN_SCISSOR_TL',
    0x200F: 'PA_SC_SCREEN_SCISSOR_BR',
    0x2080: 'PA_SC_WINDOW_OFFSET',
    0x2081: 'PA_SC_WINDOW_SCISSOR_TL',
    0x2082: 'PA_SC_WINDOW_SCISSOR_BR',
    0x210F: 'PA_CL_VPORT_XSCALE',
    0x2110: 'PA_CL_VPORT_XOFFSET',
    0x2111: 'PA_CL_VPORT_YSCALE',
    0x2112: 'PA_CL_VPORT_YOFFSET',
    0x2113: 'PA_CL_VPORT_ZSCALE',
    0x2114: 'PA_CL_VPORT_ZOFFSET',
    0x2205: 'PA_SU_SC_MODE_CNTL',
}

VIEWPORT_FLOAT_RANGE = (0x210F, 0x2114)


def read_exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise EOFError
    return b


def dump_xtr_registers(path, max_hits=5000):
    with open(path, 'rb') as f:
        # TraceHeader: uint32 version, char[40] sha, uint32 title_id
        hdr = read_exact(f, 4 + 40 + 4)
        version, = struct.unpack('<I', hdr[0:4])
        title_id, = struct.unpack('<I', hdr[44:48])
        print(f"XTR version={version} title_id=0x{title_id:08X}")
        hits = 0
        cmd_idx = 0
        prev = {}
        def maybe_print(reg_idx:int, name:str, val:int):
            nonlocal hits
            old = prev.get(reg_idx)
            if old == val:
                return
            prev[reg_idx] = val
            # Only surface non-zero changes to reduce noise
            if name.startswith('PA_CL_VPORT_'):
                fval = struct.unpack('<f', struct.pack('<I', val))[0]
                if fval == 0.0 and (old is None):
                    return
                print(f"REG {reg_idx:04X} {name:<28} f={fval:9.3f} raw=0x{val:08X}")
                hits += 1
            elif name.startswith('PA_SC_') and ('SCISSOR' in name or 'WINDOW' in name):
                x = val & 0x7FFF
                y = (val >> 16) & 0x7FFF
                if x == 0 and y == 0 and (old is None):
                    return
                print(f"REG {reg_idx:04X} {name:<28} x={x:4d} y={y:4d} raw=0x{val:08X}")
                hits += 1
            else:
                if val == 0 and (old is None):
                    return
                print(f"REG {reg_idx:04X} {name:<28} val=0x{val:08X}")
                hits += 1
        while True:
            pos = f.tell()
            tbytes = f.read(4)
            if not tbytes or len(tbytes) < 4:
                break
            t, = struct.unpack('<I', tbytes)
            cmd_type = TRACE_COMMAND_TYPE.get(t, f'Unknown({t})')
            if t == 10:  # Registers
                # RegistersCommand: u32 type, u32 first_register, u32 register_count,
                # bool execute_callbacks (1 byte) + 3 pad, u32 encoding_format, u32 encoded_length
                try:
                    rest = read_exact(f, 4 + 4 + 1 + 3 + 4 + 4)
                    first_reg, reg_count = struct.unpack('<II', rest[0:8])
                    execute_callbacks = struct.unpack('<?', rest[8:9])[0]
                    enc_format, enc_len = struct.unpack('<II', rest[12:20])
                    data = read_exact(f, enc_len)
                except EOFError:
                    break
                if enc_format != MEM_ENCODING_NONE:
                    # Skip compressed blocks (snappy) — not supported here.
                    cmd_idx += 1
                    continue
                # Uncompressed values follow, reg_count * u32
                if len(data) < reg_count * 4:
                    # Corrupt / truncated
                    cmd_idx += 1
                    continue
                # Iterate and print interesting ones
                for i in range(reg_count):
                    reg_idx = first_reg + i
                    val, = struct.unpack_from('<I', data, i * 4)
                    if reg_idx in REG_NAME:
                        name = REG_NAME[reg_idx]
                        maybe_print(reg_idx, name, val)
                    if hits >= max_hits:
                        return
            elif t in (0, 2, 4):
                # Start commands have small headers with counts; skip their payloads if present
                if t == 4:  # PacketStart has inline PM4 dwords (uncompressed)
                    rest = read_exact(f, 8)
                    base_ptr, count = struct.unpack('<II', rest)
                    payload = read_exact(f, count * 4)
                    # Walk all PM4 packets within this inline payload.
                    off = 0
                    remaining_dwords = count
                    while remaining_dwords > 0:
                        if remaining_dwords < 1:
                            break
                        packet, = struct.unpack_from('<I', payload, off)
                        packet_type = (packet >> 30) & 0x3
                        if packet_type == 0:  # TYPE0 sequential register writes
                            seq_count = ((packet >> 16) & 0x3FFF) + 1
                            base_index = packet & 0x7FFF
                            write_one = (packet >> 15) & 0x1
                            needed = 1 + seq_count
                            if remaining_dwords < needed:
                                break
                            for m in range(seq_count):
                                val, = struct.unpack_from('<I', payload, off + 4 * (1 + m))
                                reg_idx = base_index if write_one else (base_index + m)
                                if reg_idx in REG_NAME:
                                    name = REG_NAME[reg_idx]
                                    maybe_print(reg_idx, name, val)
                                    if hits >= max_hits:
                                        return
                            consumed = needed
                        elif packet_type == 1:  # TYPE1 two writes
                            # Header + 2 data dwords
                            if remaining_dwords < 3:
                                break
                            reg1 = packet & 0x7FF
                            reg2 = (packet >> 11) & 0x7FF
                            val1, = struct.unpack_from('<I', payload, off + 4)
                            val2, = struct.unpack_from('<I', payload, off + 8)
                            if reg1 in REG_NAME:
                                name1 = REG_NAME[reg1]
                                maybe_print(reg1, name1, val1)
                            if reg2 in REG_NAME:
                                name2 = REG_NAME[reg2]
                                maybe_print(reg2, name2, val2)
                            consumed = 3
                        elif packet_type == 2:  # TYPE2 NOP
                            consumed = 1
                        else:  # TYPE3 — skip over the packet
                            word_count = (packet >> 16) & 0x3FFF
                            consumed = 2 + word_count
                            if remaining_dwords < consumed:
                                break
                        remaining_dwords -= consumed
                        off += consumed * 4
                        if hits >= max_hits:
                            return
                else:
                    # Primary/Indirect start: base_ptr + count, but writer passes 0 for count; still skip 8 bytes
                    _ = read_exact(f, 8)
            elif t in (1, 3, 5):
                # End commands: no payload
                pass
            elif t in (6, 7):
                # MemoryCommand
                try:
                    rest = read_exact(f, 4 + 4 + 4 + 4)
                    base_ptr, enc_format, enc_len, dec_len = struct.unpack('<IIII', rest)
                    _ = read_exact(f, enc_len)
                except EOFError:
                    break
            elif t == 8:
                # EdramSnapshotCommand
                try:
                    rest = read_exact(f, 4 + 4)
                    enc_format, enc_len = struct.unpack('<II', rest)
                    _ = read_exact(f, enc_len)
                except EOFError:
                    break
            elif t == 9:
                # EventCommand
                _ = read_exact(f, 4)
            elif t == 11:
                # GammaRampCommand: u32 type, u8 rw_component, 3 pad, u32 enc_format, u32 enc_len
                rest = read_exact(f, 1 + 3 + 4 + 4)
                enc_format, enc_len = struct.unpack('<II', rest[4:12])
                _ = read_exact(f, enc_len)
            else:
                # Unknown — bail to avoid desync
                print(f"Unknown command type {t} at offset {pos}")
                break
            cmd_idx += 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: xtr_dump_regs.py <path-to-xtr> [max_hits]')
        sys.exit(1)
    path = sys.argv[1]
    max_hits = int(sys.argv[2]) if len(sys.argv) >= 3 else 5000
    dump_xtr_registers(path, max_hits)

