# Real-world static-analysis fixture

`sqlite3-3.54.0-x64.dll` is the official precompiled Windows x64 SQLite 3.54.0 DLL, downloaded from the [SQLite downloads page](https://www.sqlite.org/download.html) on 2026-10-15 from:

- Archive: `https://www.sqlite.org/2026/sqlite-dll-win-x64-3540000.zip`
- Official archive SHA3-256: `f5fb500c73a3afd89976386bb8e4fdc8b5b65c052e187fb1ada1f5de034cd45b`
- Extracted DLL SHA-256: `5ca6a16bdd2c5a5037b1e3a942d9ac1c66efe2def902b202d44774680a8a4656`
- PE identity: PE32+ AMD64 DLL

SQLite's [copyright/licensing page](https://www.sqlite.org/copyright.html) states that its deliverable code is dedicated to the public domain and may be copied, modified, used, compiled, sold, and distributed for any purpose. Only the DLL is retained; the adjacent `.def` file from the archive is not included.

The official package does not publish compiler version or build flags, and the Phase 5 manifest records those fields as unknown. Tests parse the DLL as static input only. They do not load, link, launch, or otherwise execute it. Its large executable section exceeds the current analysis-record budget, so decode coverage and excluded bytes are measured explicitly.
