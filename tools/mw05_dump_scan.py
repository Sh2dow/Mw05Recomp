#!/usr/bin/env python3
import os, sys, struct, argparse

BE = ">I"  # big-endian u32
LE = "<I"  # little-endian u32

MAG_MW05 = 0x3530574D  # 'MW05' in ASCII
MAG_GLAC = 0x43474C41  # 'GLAC'


def u32_be(buf, off):
    return struct.unpack_from(BE, buf, off)[0]


def u32_le(buf, off):
    return struct.unpack_from(LE, buf, off)[0]


def is_sys_ea(v):
    return (v & 0xFFFF0000) == 0x00140000


def scan_type3(buf, base_ea=0x00140000):
    hist = {}
    hits = []
    for off in range(0, len(buf) - 4, 4):
        w_be = u32_be(buf, off)
        w = struct.unpack('<I', struct.pack('>I', w_be))[0]  # byteswap to LE for bitfields
        if ((w >> 30) & 3) != 3:
            continue
        count = (w >> 16) & 0x3FFF
        opcode = (w >> 8) & 0xFF
        if count == 0 or count > 0x400:
            continue
        # payload fits?
        end_off = off + 4 * (1 + count)
        if end_off > len(buf):
            continue
        ea = base_ea + off
        hist[opcode] = hist.get(opcode, 0) + 1
        hits.append((ea, opcode, count))
    return hist, hits


def scan_nodes(buf, base_ea=0x00140000, limit=512):
    nodes = []
    for off in range(0, min(len(buf), 0x10000) - 32, 32):
        d = [u32_be(buf, off + i * 4) for i in range(8)]
        a = base_ea + off
        looks_mw = any(x == MAG_MW05 for x in d[:2] + d[4:6])
        looks_gl = (d[0] == MAG_GLAC) or (d[4] == MAG_GLAC)
        if looks_mw or looks_gl:
            nodes.append((a, d))
            if len(nodes) >= limit:
                break
    return nodes


def follow_mw05_layout_a(d):
    # d[0] == 'MW05', d[1] = EA, d[3] BE low16 as signed byte offset
    follow = d[1]
    hi16 = (d[3] >> 16) & 0xFFFF
    rel = struct.unpack("<h", struct.pack("<H", hi16))[0]
    eff = (follow + rel) & 0xFFFFFFFF
    return eff, rel


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blk13", nargs="?", default=os.path.join("out","build","x64-Clang-Debug","Mw05Recomp","traces","blk_00130000_64k.bin"))

    ap.add_argument("syscmd", nargs="?", default=os.path.join("out", "build", "x64-Clang-Debug", "Mw05Recomp", "traces", "syscmd_00140000_64k.bin"))
    args = ap.parse_args()
    path = args.syscmd
    if not os.path.exists(path):
        print(f"Missing dump: {path}")
        return 1
    buf = memoryview(open(path, "rb").read())

    print(f"Loaded {path} ({len(buf)} bytes)")

    hist, hits = scan_type3(buf)
    if hist:
        print("TYPE3 histogram:")
        for opc in sorted(hist):
            print(f"  opcode 0x{opc:02X}: {hist[opc]}")
    else:
        print("No TYPE3 headers detected")

    nodes = scan_nodes(buf)
    print(f"Node candidates: {len(nodes)} (showing up to 10)")
    for a, d in nodes[:10]:
        print(f"  ea={a:08X} d0={d[0]:08X} d1={d[1]:08X} d2={d[2]:08X} d3={d[3]:08X} d4={d[4]:08X} d5={d[5]:08X} d6={d[6]:08X} d7={d[7]:08X}")
        if d[0] == MAG_MW05 and is_sys_ea(d[1]):
            eff, rel = follow_mw05_layout_a(d)
            print(f"    layoutA follow={d[1]:08X} rel={rel} => eff={eff:08X}")

    # Try scanning around the common stub 0x00140410 if present
    off = 0x00140410 - 0x00140000
    if 0 <= off < len(buf) - 64:
        d = [u32_be(buf, off + i * 4) for i in range(8)]
        print(f"At 00140410: d0={d[0]:08X} d1={d[1]:08X} d2={d[2]:08X} d3={d[3]:08X} d4={d[4]:08X} d5={d[5]:08X} d6={d[6]:08X} d7={d[7]:08X}")

        # Decode parameters of the op=04 block at this location (assumes count = 0x14 typical observed)
        hdr_be = u32_be(buf, off)
        hdr_le = struct.unpack('<I', struct.pack('>I', hdr_be))[0]
        count = (hdr_le >> 16) & 0x3FFF
        opcode = (hdr_le >> 8) & 0xFF
        print(f"Header decode: type={(hdr_le>>30)&3} count={count} opcode=0x{opcode:02X}")
        param_count = min(count, 20)
        params = [u32_be(buf, off + 4*(1+i)) for i in range(param_count)]
        print("Params (BE words):")
        for i, w in enumerate(params):
            print(f"  p{i:02d} = {w:08X}")
        print("Interpreted (rel_dw|size_hint, base_ea) pairs:")
        for i in range(0, param_count-1, 2):
            w = params[i]
            base = params[i+1]
            rel_dw = struct.unpack('<h', struct.pack('<H', (w >> 16) & 0xFFFF))[0]
            size_hint = w & 0xFFFF
            eff = (base + rel_dw*4) & 0xFFFFFFFF
            print(f"  pair{i//2}: rel_dw={rel_dw:6d} size_hint={size_hint:5d} base={base:08X} -> eff={eff:08X} sys={'Y' if is_sys_ea(eff) else 'N'}")
    # If blk_00130000_64k.bin exists, dump a small window around eff=0x0013C3FC (offset 0xC3FC)
    blk = args.blk13
    if os.path.exists(blk):
        bbuf = memoryview(open(blk, 'rb').read())
        off13 = 0x0013C3FC - 0x00130000
        if 0 <= off13 <= len(bbuf) - 32:
            words = [u32_be(bbuf, off13 + i*4) for i in range(8)]
            print(f"blk13 @ 0013C3FC: w0={words[0]:08X} w1={words[1]:08X} w2={words[2]:08X} w3={words[3]:08X} w4={words[4]:08X} w5={words[5]:08X} w6={words[6]:08X} w7={words[7]:08X}")

    # Dump syscmd words at 001403F8 as referenced by pair1
    off_sys = 0x001403F8 - 0x00140000
    if 0 <= off_sys <= len(buf) - 32:
        sw = [u32_be(buf, off_sys + i*4) for i in range(8)]
        print(f"syscmd @ 001403F8: w0={sw[0]:08X} w1={sw[1]:08X} w2={sw[2]:08X} w3={sw[3]:08X} w4={sw[4]:08X} w5={sw[5]:08X} w6={sw[6]:08X} w7={sw[7]:08X}")


    return 0


if __name__ == "__main__":
    sys.exit(main())

