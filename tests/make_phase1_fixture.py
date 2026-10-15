#!/usr/bin/env python3
"""Build small deterministic PE fixtures; none of the generated images is executable in the test workflow."""
import argparse
import pathlib
import struct

IMAGE_BASE = 0x140000000


def put16(data, off, value):
    struct.pack_into("<H", data, off, value)


def put32(data, off, value):
    struct.pack_into("<I", data, off, value)


def put64(data, off, value):
    struct.pack_into("<Q", data, off, value)


def build_pe(machine=0x8664, clr=False):
    data = bytearray(0x900)
    data[0:2] = b"MZ"
    put32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    put16(data, coff, machine)
    put16(data, coff + 2, 3)
    put16(data, coff + 16, 0xF0)
    put16(data, coff + 18, 0x0022)

    opt = 0x98
    put16(data, opt, 0x20B)
    put32(data, opt + 4, 0x10)
    put32(data, opt + 16, 0x1000)
    put32(data, opt + 20, 0x1000)
    put64(data, opt + 24, IMAGE_BASE)
    put32(data, opt + 32, 0x1000)
    put32(data, opt + 36, 0x200)
    put32(data, opt + 56, 0x4000)
    put32(data, opt + 60, 0x200)
    put16(data, opt + 68, 3)
    put16(data, opt + 70, 0x8160)
    put32(data, opt + 108, 16)

    section_table = 0x188
    sections = [
        (b".text", 0x10, 0x1000, 8, 0x200, 0x60000020),
        (b".rdata", 0x300, 0x2000, 0x300, 0x400, 0x40000040),
        (b".pdata", 0x200, 0x3000, 0x200, 0x700, 0x40000040),
    ]
    for index, (name, vsize, rva, raw_size, raw_offset, flags) in enumerate(sections):
        off = section_table + index * 40
        data[off:off + len(name)] = name
        put32(data, off + 8, vsize)
        put32(data, off + 12, rva)
        put32(data, off + 16, raw_size)
        put32(data, off + 20, raw_offset)
        put32(data, off + 36, flags)

    # .text: two known instructions, an invalid byte, a valid NOP, then a truncated CALL.
    data[0x200:0x208] = bytes.fromhex("48 89 d8 c3 06 90 e8 01")

    # Export directory, function/name/ordinal arrays and strings in .rdata.
    rdata = 0x400
    struct.pack_into("<IIHHIIIIIII", data, rdata,
                     0, 0, 0, 0, 0x2060, 1, 1, 1, 0x2030, 0x2034, 0x2038)
    put32(data, rdata + 0x30, 0x1000)
    put32(data, rdata + 0x34, 0x2040)
    put16(data, rdata + 0x38, 0)
    data[rdata + 0x40:rdata + 0x40 + 14] = b"exported_func\0"
    data[rdata + 0x60:rdata + 0x60 + 12] = b"fixture.dll\0"
    put32(data, opt + 112 + 0 * 8, 0x2000)
    put32(data, opt + 112 + 0 * 8 + 4, 0x80)

    # Import descriptor, lookup/IAT arrays, library and hint/name.
    struct.pack_into("<IIIII", data, rdata + 0x80, 0x20C0, 0, 0, 0x20A8, 0x20D0)
    data[rdata + 0x80 + 20:rdata + 0x80 + 40] = bytes(20)
    data[rdata + 0xA8:rdata + 0xA8 + 13] = b"KERNEL32.dll\0"
    put64(data, rdata + 0xC0, 0x20E0)
    put64(data, rdata + 0xC8, 0)
    put64(data, rdata + 0xD0, 0x20E0)
    put64(data, rdata + 0xD8, 0)
    put16(data, rdata + 0xE0, 0)
    data[rdata + 0xE2:rdata + 0xE2 + 12] = b"ExitProcess\0"
    put32(data, opt + 112 + 1 * 8, 0x2080)
    put32(data, opt + 112 + 1 * 8 + 4, 40)

    # One DIR64 relocation block.
    struct.pack_into("<IIHH", data, rdata + 0x130, 0x1000, 12, 0xA005, 0)
    put32(data, opt + 112 + 5 * 8, 0x2130)
    put32(data, opt + 112 + 5 * 8 + 4, 12)

    # RSDS debug record with stable GUID/age/path.
    cv_record = b"RSDS" + bytes(range(16)) + struct.pack("<I", 1) + b"fixture.pdb\0"
    struct.pack_into("<IIHHIIII", data, rdata + 0x150, 0, 0, 0, 0, 2, len(cv_record), 0x2180, 0x580)
    data[rdata + 0x180:rdata + 0x180 + len(cv_record)] = cv_record
    put32(data, opt + 112 + 6 * 8, 0x2150)
    put32(data, opt + 112 + 6 * 8 + 4, 28)

    # TLS directory with one callback.
    struct.pack_into("<QQQQII", data, rdata + 0x1B0,
                     0, 0, 0, IMAGE_BASE + 0x21F0, 4, 0)
    put64(data, rdata + 0x1F0, IMAGE_BASE + 0x1000)
    put64(data, rdata + 0x1F8, 0)
    put32(data, opt + 112 + 9 * 8, 0x21B0)
    put32(data, opt + 112 + 9 * 8 + 4, 40)

    # x64 RUNTIME_FUNCTION with a small valid UNWIND_INFO record.
    struct.pack_into("<III", data, 0x700, 0x1000, 0x1008, 0x3010)
    data[0x710:0x714] = bytes((1, 1, 0, 0))
    put32(data, opt + 112 + 3 * 8, 0x3000)
    put32(data, opt + 112 + 3 * 8 + 4, 12)

    if clr:
        # IMAGE_COR20_HEADER and a small metadata signature, intentionally treated as managed/unsupported.
        clr_rva = 0x2240
        clr_off = rdata + (clr_rva - 0x2000)
        put32(data, clr_off, 72)
        put32(data, clr_off + 8, 0x22A0)
        put32(data, clr_off + 12, 8)
        put32(data, clr_off + 16, 1)
        put32(data, clr_off + 20, 0x06000001)
        data[rdata + 0x2A0:rdata + 0x2A8] = b"BSJB\x01\x00\x01\x00"
        put32(data, opt + 112 + 14 * 8, clr_rva)
        put32(data, opt + 112 + 14 * 8 + 4, 72)
    return bytes(data)


def build_auto_function_range_pe():
    """Create an inert large PE that crosses auto mode's size and range-count thresholds."""
    function_count = 512
    text_size = 0x800000
    pdata_va = 0x801000
    pdata_raw = 0x800200
    exception_size = function_count * 12
    pdata_raw_size = 0x4000
    data = bytearray(pdata_raw + pdata_raw_size)
    data[0:2] = b"MZ"
    put32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    put16(data, coff, 0x8664)
    put16(data, coff + 2, 2)
    put16(data, coff + 16, 0xF0)
    put16(data, coff + 18, 0x0022)
    opt = 0x98
    put16(data, opt, 0x20B)
    put32(data, opt + 4, text_size)
    put32(data, opt + 16, 0x1000)
    put32(data, opt + 20, 0x1000)
    put64(data, opt + 24, IMAGE_BASE)
    put32(data, opt + 32, 0x1000)
    put32(data, opt + 36, 0x200)
    put32(data, opt + 56, 0x805000)
    put32(data, opt + 60, 0x200)
    put16(data, opt + 68, 3)
    put16(data, opt + 70, 0x8160)
    put32(data, opt + 108, 16)

    section_table = 0x188
    sections = [
        (b".text", text_size, 0x1000, text_size, 0x200, 0x60000020),
        (b".pdata", pdata_raw_size, pdata_va, pdata_raw_size, pdata_raw, 0x40000040),
    ]
    for index, (name, vsize, rva, raw_size, raw_offset, flags) in enumerate(sections):
        off = section_table + index * 40
        data[off:off + len(name)] = name
        put32(data, off + 8, vsize)
        put32(data, off + 12, rva)
        put32(data, off + 16, raw_size)
        put32(data, off + 20, raw_offset)
        put32(data, off + 36, flags)

    put32(data, opt + 112 + 3 * 8, pdata_va)
    put32(data, opt + 112 + 3 * 8 + 4, exception_size)
    unwind_base_rva = pdata_va + exception_size
    unwind_base_offset = pdata_raw + exception_size
    for index in range(function_count):
        begin_rva = 0x1000 + index * 16
        text_offset = 0x200 + index * 16
        data[text_offset:text_offset + 16] = b"\x90" * 15 + b"\xc3"
        entry_offset = pdata_raw + index * 12
        put32(data, entry_offset, begin_rva)
        put32(data, entry_offset + 4, begin_rva + 16)
        put32(data, entry_offset + 8, unwind_base_rva + index * 4)
        data[unwind_base_offset + index * 4:unwind_base_offset + index * 4 + 4] = bytes((1, 0, 0, 0))
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--machine", type=lambda value: int(value, 0), default=0x8664)
    parser.add_argument("--clr", action="store_true")
    parser.add_argument("--auto-function-ranges", action="store_true")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fixture = build_auto_function_range_pe() if args.auto_function_ranges else build_pe(machine=args.machine, clr=args.clr)
    args.output.write_bytes(fixture)


if __name__ == "__main__":
    main()
