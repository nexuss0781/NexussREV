#!/usr/bin/env python3
"""Generate the deterministic, non-executable minimal PE32+ fixture used in Phase 0 tests."""

import pathlib
import struct


def make_fixture():
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # IMAGE_FILE_MACHINE_AMD64
        1,       # one section
        0,       # timestamp
        0, 0,    # no COFF symbol table
        0xF0,    # PE32+ optional-header size
        0x0022,  # executable image, large-address aware
    )
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)              # PE32+
    struct.pack_into("<I", optional, 4, 0x200)              # code size
    struct.pack_into("<I", optional, 16, 0x1000)             # entry point RVA
    struct.pack_into("<I", optional, 20, 0x1000)             # base of code
    struct.pack_into("<Q", optional, 24, 0x140000000)       # image base
    struct.pack_into("<II", optional, 32, 0x1000, 0x200)    # section/file alignment
    struct.pack_into("<HHHHHH", optional, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", optional, 56, 0x2000)             # image size
    struct.pack_into("<I", optional, 60, 0x200)              # headers size
    struct.pack_into("<H", optional, 68, 3)                  # console subsystem
    struct.pack_into("<H", optional, 70, 0x8160)             # DLL characteristics
    struct.pack_into("<QQQQ", optional, 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", optional, 108, 16)                # directory count

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0", 1, 0x1000, 0x200, 0x200,
        0, 0, 0, 0, 0x60000020,  # code, readable, executable
    )
    headers = bytes(dos) + b"PE\0\0" + coff + bytes(optional) + section
    assert len(headers) == 0x1B0
    headers += bytes(0x200 - len(headers))
    code = b"\xC3" + bytes(0x1FF)  # RET followed by deterministic padding
    return headers + code


if __name__ == "__main__":
    output = pathlib.Path(__file__).parent / "fixtures" / "minimal-pe-x64.exe"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(make_fixture())
    print(f"Wrote {output} ({output.stat().st_size} bytes)")
