# Phase 2 PE/PDB fixtures

All fixture code in this directory is original NexussREV test source (`corpus.c`, SHA-256 `9bbbf1c673ce7365a51b28d9a9cbe3b9cc9bea045baf718c856a65c1ba880d92`). The PE images are never launched by tests; they are parsed as untrusted static data.

The checked-in reference artifacts were produced with Ubuntu Clang 18.1.3 (`1ubuntu1`) targeting `x86_64-pc-windows-msvc` and LLD 18.1.3. From this directory, the equivalent link inputs are generated using:

```sh
clang++ --target=x86_64-pc-windows-msvc -x c -g -gcodeview -O0 -fno-inline -c corpus.c -o /tmp/nexussrev-o0.obj
lld-link /dll /noentry /debug /pdb:pdb-sample.pdb /out:pdb-sample.dll /export:add_one /export:call_add /export:call_helper /tmp/nexussrev-o0.obj
clang++ --target=x86_64-pc-windows-msvc -x c -g -gcodeview -O2 -c corpus.c -o /tmp/nexussrev-o2.obj
lld-link /dll /noentry /debug /pdb:pdb-sample-o2.pdb /out:pdb-sample-o2.dll /export:add_one /export:call_add /export:call_helper /tmp/nexussrev-o2.obj
lld-link /entry:add_one /subsystem:console /nodefaultlib /debug /pdb:pdb-exe-o0.pdb /out:pdb-exe-o0.exe /tmp/nexussrev-o0.obj
lld-link /entry:add_one /subsystem:console /nodefaultlib /debug /pdb:pdb-exe-o2.pdb /out:pdb-exe-o2.exe /tmp/nexussrev-o2.obj
```

The DLL and EXE links use the matching O0/O2 objects. The DLL commands export the three public functions; the EXE commands use `add_one` as an entry point, but the generated EXEs are **never executed**. The DLLs and EXEs have matching RSDS GUID/age records and private CodeView procedure records. Their checked-in PDBs are independently matched by identity during the test.

The files under `stripped/` are byte-for-byte copies of those PE outputs except that the export (data directory 0) and debug/CodeView (directory 6) directory entries were zeroed. The exception/unwind directory (directory 3), executable bytes, and section layout are retained. The equivalent operation is:

```python
import struct
from pathlib import Path

data = bytearray(Path("pdb-sample.dll").read_bytes())
pe = struct.unpack_from("<I", data, 0x3C)[0]
optional_header = pe + 24
assert struct.unpack_from("<H", data, optional_header)[0] == 0x20B
directories = optional_header + 112  # PE32+ data-directory array
for index in (0, 6):  # export and debug/CodeView
    struct.pack_into("<II", data, directories + index * 8, 0, 0)
Path("stripped/pdb-sample-stripped.dll").write_bytes(data)
```

This intentionally removes names and PDB identity so tests measure fallback evidence rather than symbol labels. Exact labeled ranges are maintained separately in [`../../benchmarks/v1/corpus.json`](../../benchmarks/v1/corpus.json), with expected PE/PDB hashes and thresholds.

The local fixture corpus covers EXEs and DLLs, O0 and O2, matching PDBs, and PDB-stripped images with no export or CodeView directory. It is a versioned test baseline, not a representative sample of all Windows compilers or arbitrary executables. Additional toolchain families require independently built, labeled fixture sets before any thresholds are raised.
