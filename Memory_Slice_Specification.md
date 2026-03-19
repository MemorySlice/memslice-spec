# Memory Slice (.msl) — Binary Format Specification

**Version:** 1.0.0  
**Status:** Working Draft

---

## Abstract

Memory Slice (`.msl`) is a self-describing, block-based binary format for capturing the forensic state of a single operating system process. It records both the virtual address space (with per-page acquisition status) and transient OS-queryable metadata that exists only while the process is alive. This document specifies the binary layout: file header, block architecture, integrity chain, capture-time payloads, cross-referencing, capability bitmap, and raw dump import mechanism.

This specification accompanies the research paper *Memory Slice: A Process-Centric Dump Format Enabling Differential Structure Discovery in Memory Forensics*. The differential analysis algorithm, MemDiver framework, and evaluation are outside this document's scope.

---

## 1. Scope and Conventions

### 1.1 Scope

This document defines the binary wire format of Memory Slice (`.msl`) files. It does *not* specify acquisition procedures or analysis algorithms.

### 1.2 Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, "RECOMMENDED", **MAY**, and **OPTIONAL** are per RFC 2119.

### 1.3 Encoding Conventions

- The file header's `Endianness` byte at offset `0x08` determines byte order for all multi-byte integers. `0x01` = little-endian (default); `0x02` = big-endian. Producers **SHOULD** use little-endian unless the target platform is natively big-endian.
- Strings are UTF-8, null-terminated, padded to **8-byte** boundaries with zero bytes. `pad8(n) = ⌈n/8⌉ × 8`. All padding bytes **MUST** be `0x00`.
- Variable-length fields (`PageStateMap`, `NativeBlob`) are padded to 8-byte boundaries.
- UUIDs **MUST** be version 4 (random) per RFC 4122, stored as 16 raw bytes in RFC 4122 network byte order, regardless of file `Endianness`.
- Hashes use BLAKE3 with 32-byte output (Section 4.4).
- Timestamps: unsigned 64-bit nanoseconds since Unix epoch (1970-01-01T00:00:00Z).
- All `Reserved` fields **MUST** be zero (producers) and **MUST** be ignored (consumers).

### 1.4 UUID Requirements

All UUID fields **MUST** be version 4 (random) per RFC 4122. The 4-bit version field (bits 48–51) **MUST** be `0100`; the 2-bit variant (bits 64–65) **MUST** be `10`.

> **Implementation guidance:** A thread-local fast PRNG such as `xoshiro256++` or `PCG64`, seeded once from OS entropy, provides sufficient uniqueness (~2⁻⁶¹ collision probability per pair) without CSRNG overhead.

### 1.5 Terminology

- **Producer** — Software that creates or appends blocks.
- **Consumer** — Software that reads an MSL file.
- **Acquirer** — A producer capturing live process state (types `0x0000`–`0x0FFF`).
- **Importer** — A producer converting a raw dump into MSL (Section 9).
- **Block** — Fixed header + variable payload.
- **Payload** — Block-type-specific data after the header.

---

## 2. Format Overview

An MSL file is a linear byte stream: a **file header** (64 bytes in v1.0) followed by **typed, length-prefixed blocks**. No inter-block gaps. `HeaderSize` tells the consumer where blocks begin. Figure 1 (PDF) shows the high-level structure; Figure 2 (PDF) shows a typical live-acquisition block sequence.

**Typical live-acquisition block sequence:**

```
File Header
  → Block 0:  Process Identity (0x0040) — who is this process?
  → Block 1:  Module List Index (0x0010) — manifest with pre-assigned UUIDs
  → Block 2+: Memory Regions (0x0001) — virtual address space pages
  → ...       Module Entries (0x0002) — full metadata (using pre-assigned UUIDs)
  → ...       Key Hints (0x0020) — optional crypto key location annotations
  → Last:     End-of-Capture (0x0FFF) — completeness marker
```

Block 0's `PrevHash` = BLAKE3(File Header), anchoring the integrity chain. Each subsequent block hashes its predecessor. Consumers detect end-of-file when fewer than 80 bytes remain or the next 4 bytes do not match the block magic (`0x4D534C43`). The header has no block count — appending blocks would require mutating it, violating append-only integrity.

### 2.1 Design Principles

1. **Integrity Verification (Append-Only Policy, Anchored Hash Chain).** Producers treat all written blocks as append-only. The BLAKE3 chain enables consumers to detect accidental corruption or post-hoc modification (Section 2.2).
2. **Epistemic Honesty (Three-State Pages).** Captured vs. Failed vs. Unmapped.
3. **Self-Describing.** Endianness, version, header size, OS, arch, PID, capabilities.
4. **Dual-Layer OS Abstraction.** Normalized fields + OS-native opaque blob.

### 2.2 Scope of the Integrity Guarantee

The hash chain provides *tamper detection*, not *tamper resistance*. Because the chain uses an unkeyed hash function, any party with write access can modify a block and recompute all subsequent hashes. The chain protects against **accidental corruption** (bit-rot, truncation, transfer errors) and detects **naive modification** (altering a block without updating the chain). It does *not* protect against an adversary who deliberately rewrites the file.

For scenarios requiring tamper evidence admissible in legal or regulatory contexts, producers **SHOULD** complement the in-file hash chain with external mechanisms such as a digital signature (e.g., Ed25519) over the EoC `FileHash`, a timestamped hash commitment to a trusted third party (RFC 3161), or write-once storage media. In the absence of such mechanisms, the in-file hash chain alone **MUST NOT** be represented as providing forensic-grade tamper evidence.

---

## 3. File Header

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 8 | `Magic` | `0x4D454D534C494345` ("MEMSLICE"). Endianness-independent. |
| `0x08` | 1 | `Endianness` | `0x01`=LE, `0x02`=BE. Invalid values **MUST** cause rejection. |
| `0x09` | 1 | `HeaderSize` | Header size in bytes (`uint8`). v1.0: **MUST** be 64 (`0x40`). |
| `0x0A` | 2 | `Version` | `uint16` read per `Endianness`. Major in high byte, minor in low byte. v1.0: `0x0100` (=256). |
| `0x0C` | 4 | `Flags` | Bit 0: `Imported` (file created by importing a raw dump, not live acquisition). Bits 1–31: reserved, zero. |
| `0x10` | 8 | `CapBitmap` | Capability bitmap (Section 8). |
| `0x18` | 16 | `DumpUUID` | UUIDv4 uniquely identifying this dump. Used for cross-file referencing (Related Dump blocks reference another file's `DumpUUID`), deduplication, and case management. |
| `0x28` | 8 | `Timestamp` | Acquisition start (UTC wall-clock, nanoseconds since Unix epoch 1970-01-01T00:00:00Z). |
| `0x30` | 2 | `OSType` | Target OS (Section 3.3). |
| `0x32` | 2 | `ArchType` | Target CPU (Section 3.3). |
| `0x34` | 4 | `PID` | Process ID at acquisition. |
| `0x38` | 1 | `ClockSource` | `0x00`=Unknown, `0x01`=`CLOCK_REALTIME`, `0x02`=`CLOCK_MONOTONIC_RAW`, `0x03`=`QueryPerformanceCounter`, `0x04`=`mach_absolute_time`. `0xFF`=Other. Producers **SHOULD** use a monotonic source for per-region timestamps. |
| `0x39` | 7 | `Reserved` | **MUST** be zero. |

**Size:** 8+1+1+2+4+8+16+8+2+2+4+1+7 = 64.

### 3.1 Endianness Bootstrapping

**Parse sequence:** (1) Read 8-byte magic. (2) Read `Endianness` at `0x08`. (3) Read `HeaderSize` at `0x09`. (4) All subsequent multi-byte reads use the determined order.

Memory content within `PageData` is stored in the *target architecture's* native order; `Endianness` governs only format-level structural integers.

### 3.2 Version Compatibility

Unknown major version: **SHOULD** reject. Unknown minor of known major: **MAY** parse. Always use `HeaderSize` to locate Block 0.

### 3.3 Platform Codes

**OS type codes:** `0x0000`=Windows, `0x0001`=Linux, `0x0002`=macOS, `0x0003`=Android, `0x0004`=iOS/iPadOS, `0x0005`=FreeBSD, `0x0006`=NetBSD, `0x0007`=OpenBSD, `0x0008`=QNX, `0x0009`=Fuchsia. `0x000A`–`0x00FF`=Reserved. `0x0100`–`0xFFFE`=Vendor. `0xFFFF`=Unknown.

**Architecture codes:** `0x0000`=x86, `0x0001`=x86_64, `0x0002`=ARM64, `0x0003`=ARM32, `0x0004`=MIPS32, `0x0005`=MIPS64, `0x0006`=RISC-V RV32, `0x0007`=RISC-V RV64, `0x0008`=PPC32, `0x0009`=PPC64, `0x000A`=s390x, `0x000B`=LoongArch64. `0x000C`–`0x00FF`=Reserved. `0x0100`–`0xFFFE`=Vendor. `0xFFFF`=Unknown.

---

## 4. Block Architecture

Every block consists of a **fixed 80-byte Common Block Header** followed by a **variable-length payload**. The Common Block Header has the same layout regardless of block type, enabling forward compatibility.

### 4.1 Common Block Header (80 bytes)

See Figure 3 (PDF) for the visual layout.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `0x00` | 4 | `Magic` | `0x4D534C43` ("MSLC"). |
| `0x04` | 2 | `BlockType` | Payload selector (Section 4.3). |
| `0x06` | 2 | `Flags` | Per-block flags (Section 4.2). |
| `0x08` | 4 | `BlockLength` | Total size (hdr+payload). ≥ 80. |
| `0x0C` | 2 | `PayloadVersion` | Payload layout version. Default: `0x0001`. Skip unknown versions via `BlockLength`. |
| `0x0E` | 2 | `Reserved` | **MUST** be zero. |
| `0x10` | 16 | `BlockUUID` | UUIDv4 identifier. 8-byte aligned. |
| `0x20` | 16 | `ParentUUID` | Parent UUID or zeros. 8-byte aligned. |
| `0x30` | 32 | `PrevHash` | BLAKE3 of preceding element (Section 4.4). 8-byte aligned. |
| `0x50` | var | `Payload` | `BlockLength − 80` bytes. |

**Verification:** 4+2+2+4+2+2+16+16+32 = 80.

Every block begins with this header. The `BlockType` selects the payload layout; `BlockLength` enables skipping unknown types; `PrevHash` anchors the integrity chain. The `PayloadVersion` allows future evolution of a payload layout without allocating a new block type.

### 4.2 Block Flags

| Bit(s) | Name | Description |
|--------|------|-------------|
| 0 | `Compressed` | Algorithm in bits 1–2. |
| 1–2 | `CompAlgo` | `00`=none, `01`=zstd, `10`=lz4, `11`=reserved. |
| 3 | `HasKeyHints` | One or more Key Hint blocks (`0x0020`) reference this block. |
| 4 | `HasChildren` | Referenced via `ParentUUID`. |
| 5 | `Continuation` | Continuation fragment. `ParentUUID` references first fragment. |
| 6–15 | `Reserved` | Zero. |

**CompAlgo semantics.** If `Compressed` (bit 0) is not set, a consumer **MUST** ignore bits 1–2. A producer **MUST** set bits 1–2 to `00` when `Compressed` is not set. The value `11` is reserved for future "extended" use: the compression algorithm identifier would then appear in the first 2 bytes of the payload.

### 4.3 Block Type Registry

| Range | Namespace | Writer | Description |
|-------|-----------|--------|-------------|
| `0x0000`–`0x0FFF` | Capture-Time | Acquirer/Importer | Regions, modules, threads, keys, import provenance |
| `0x1000`–`0x1FFF` | Structural | Analysis tool | VAS map, pointer graph (navigational aids only) |
| `0x2000`–`0xFFFF` | *Reserved* | — | Reserved for future specification versions. |

**Defined block types:**

| Type | Name | Description |
|------|------|-------------|
| `0x0000` | *Invalid* | Reserved. **MUST NOT** appear in a valid file. |
| `0x0001` | Memory Region | Per-page memory (Section 5.1). |
| `0x0002` | Module Entry | Module metadata (Section 5.2). |
| `0x0010` | Module List Index | Module manifest with pre-assigned UUIDs (Section 5.3). **MUST** be Block 1. |
| `0x0011` | Thread Context | Register state. |
| `0x0012` | File Descriptor | Open handle. |
| `0x0013` | Network Connection | Socket attribution. |
| `0x0014` | Environment Block | Env vars. |
| `0x0015` | Security Token | Credentials. |
| `0x0020` | Key Hint | Cryptographic key location annotation (Section 5.6). |
| `0x0030` | Import Provenance | Raw dump metadata (Section 9). |
| `0x0040` | Process Identity | Executable path, command line, PPID (Section 5.4). |
| `0x0041` | Related Dump | Cross-file reference (Section 5.5). |
| `0x0FFF` | End-of-Capture | Completeness marker and acquisition end time (Section 4.5). |
| `0x1001` | VAS Map | Reconstructed virtual address space. |
| `0x1003` | Pointer Graph | Pointer relationships between regions. |

Analysis results (structure candidates, annotations, scan signatures) are outside this format's scope and belong in the analysis tool's own output.

### 4.4 Integrity Chain (PrevHash)

The chain uses BLAKE3 with 32-byte (256-bit) output, selected for throughput (3–4× faster than SHA-256 with SIMD). Collision resistance (128-bit birthday bound) is equivalent to SHA-256; the choice is motivated by performance, not security margin.

- **Block 0:** `PrevHash = BLAKE3(File Header, all HeaderSize bytes)`.
- **Block i (i ≥ 1):** `PrevHash = BLAKE3(Block_{i-1}, all BlockLength bytes)`.

**Wire-format hashing.** The `PrevHash` is computed over *raw on-disk bytes*. If a block is compressed, the hash covers the compressed wire format, not the decompressed content.

### 4.5 End-of-Capture Block (0x0FFF)

The EoC serves as a **completeness marker**: its presence confirms the acquirer finished normally, and its payload (Table: EoC) records the acquisition end time.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 32 | `FileHash` | BLAKE3 of all bytes from offset 0 through the last byte before this EoC block. |
| `+0x20` | 8 | `AcqEnd` | Acquisition end time (UTC, nanoseconds since Unix epoch). |
| `+0x28` | 8 | `Reserved` | **MUST** be zero. |

**Completeness and corruption detection.** If present, the consumer knows the acquirer finished normally. `FileHash` enables corruption detection (verify PrevHash chain, then verify FileHash). If absent, the dump may be incomplete. Note that `FileHash`, like the PrevHash chain, uses an unkeyed hash and does not provide tamper resistance (see Section 2.2).

> **Implementation guidance:** Producers **SHOULD** maintain a running BLAKE3 hasher state during acquisition to avoid a second pass when writing the EoC.

---

## 5. Capture-Time Payloads

Payload data begins at byte `0x50` within each block (immediately after the 80-byte Common Block Header). All offsets below are relative to the payload start.

Each block has exactly **one type**. The `BlockType` in the Common Block Header determines which payload layout follows at offset `0x50`. If the same virtual address range is both captured as raw memory and described with module metadata, these are two separate blocks — linked by cross-referencing (Section 7), not merged into one.

### 5.1 Memory Region (0x0001)

A Memory Region block stores the raw byte content of a contiguous range of virtual address space — the actual memory pages that an analysis tool will examine for structures, strings, and key material. Each captured region is stored as a separate block (see Figure 4 in the PDF for the layout). An acquirer **SHOULD** emit one block per contiguous virtual address range as enumerated by the operating system (e.g., via `VirtualQuery` on Windows or `/proc/pid/maps` on Linux). Because acquisition is not atomic, individual pages may become unreadable or unmapped between enumeration and read time; the `PageStateMap` records this per-page outcome (see Section 6).

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 8 | `BaseAddr` | Virtual address of the region's first byte. |
| `+0x08` | 8 | `RegionSize` | Region size in bytes. **MUST** be a multiple of `2^PageSizeLog2`. |
| `+0x10` | 1 | `Protection` | Bit 0=R, 1=W, 2=X, 3=Guard, 4=CopyOnWrite. Bits 5–7 reserved. |
| `+0x11` | 1 | `RegionType` | `0x00`=Unknown, `01`=Heap, `02`=Stack, `03`=Image, `04`=MappedFile, `05`=Anonymous, `06`=SharedMem, `FF`=Other. |
| `+0x12` | 1 | `PageSizeLog2` | Power-of-two exponent: page size = `2^PageSizeLog2` bytes. 12 = 4 KiB; 21 = 2 MiB; 30 = 1 GiB. **MUST** be in [10, 40]; values outside **MUST** cause rejection. |
| `+0x13` | 5 | `Reserved` | **MUST** be zero. |
| `+0x18` | 8 | `Timestamp` | Time this region was acquired (UTC, nanoseconds since Unix epoch). |
| `+0x20` | var | `PageStateMap` | 2 bits per page (Section 6). Padded to 8-byte boundary. |
| `+m` | var | `PageData` | Concatenated bytes of Captured pages only. |

**PageStateMap size.** Let `PageSize = 2^PageSizeLog2` and `P = RegionSize >> PageSizeLog2`: `map_bytes = pad8((P + 3) / 4)`.

> **Regions exceeding BlockLength capacity:** `BlockLength` is a `uint32`, limiting any single block to ~4.29 GiB. Ranges exceeding this **MUST** be split into multiple Memory Region blocks. Each **continuation block** sets the `Continuation` flag (bit 5) and `ParentUUID` to the first fragment's `BlockUUID`. The first fragment sets `HasChildren` (bit 4). Consumers reassemble by sorting on `BaseAddr`.

### 5.2 Module Entry (0x0002)

While a Memory Region stores raw bytes, a Module Entry stores the *identity and metadata* of a loaded library (DLL, shared object, or dynamic library): its file path, version, on-disk hash, and OS-native loader data. This metadata is essential for interpreting the raw bytes — without knowing which allocator produced a heap region, the byte patterns are opaque. Each loaded module is stored as a separate block whose `ParentUUID` **MUST** reference the Module List Index (`0x0010`). The `BlockUUID` **MUST** match the pre-assigned `ModuleUUID` from the manifest (Section 5.3).

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 8 | `BaseAddr` | Load address. |
| `+0x08` | 8 | `ModuleSize` | Mapping size. |
| `+0x10` | 2 | `PathLen` | Byte length of `Path` (incl. null). Stored size: `pad8(PathLen)`. |
| `+0x12` | 2 | `VersionLen` | Byte length of `Version` (incl. null). 0 if unavailable. |
| `+0x14` | 4 | `Reserved` | Zero. |
| `+0x18` | var | `Path` | UTF-8, pad8. |
| `+p` | var | `Version` | `p = 0x18 + pad8(PathLen)`. |
| `+v` | 32 | `DiskHash` | BLAKE3 of on-disk binary. `v = p + pad8(VersionLen)`. |
| `+v+32` | 4 | `BlobLen` | NativeBlob size. |
| `+v+36` | 4 | `Reserved2` | Zero. |
| `+v+40` | var | `NativeBlob` | OS-native opaque data. |

**DiskHash unavailability.** If the on-disk binary is inaccessible (deleted file, `memfd`, fileless malware), the acquirer **MUST** write 32 zero bytes. A consumer **MUST** treat all-zero `DiskHash` as "hash not available."

**Why module metadata matters.** The exact version of `ntdll.dll` determines NT Heap chunk layout and XOR key; the exact `libc` determines glibc `malloc` chunk format. Without this information, a heap dump is opaque. The `NativeBlob` provides additional OS-specific context. Producers **SHOULD** populate it as follows: on Windows (`0x0000`), a serialized `LDR_DATA_TABLE_ENTRY`; on Linux (`0x0001`), the corresponding line from `/proc/pid/maps` (or `smaps`) as a UTF-8 string, null-terminated; on macOS (`0x0002`), a serialized `dyld_image_info` structure; on Android (`0x0003`), the same as Linux plus ART-specific metadata if available.

### 5.3 Module List Index (0x0010)

An acquirer **MUST** emit the Module List Index as Block 1 (immediately after the Process Identity block; see Figure 5 in the PDF for the payload layout). The acquirer first enumerates all loaded modules, pre-generates a UUIDv4 for each future Module Entry block, and writes a lightweight **manifest**. This allows a consumer to build a complete module map after reading only two blocks — before any Memory Region or Module Entry is encountered.

The full Module Entry blocks (Section 5.2) are emitted later and **MUST** use the pre-assigned UUID from the manifest as their `BlockUUID`. Their `ParentUUID` **MUST** reference this Module List Index.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 4 | `EntryCount` | Number of module manifest entries. |
| `+0x04` | 4 | `Reserved` | Zero. |
| `+0x08` | var | `Entries` | `EntryCount` variable-size entries (see below). |

**Module manifest entry (variable-size):**

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 16 | `ModuleUUID` | Pre-assigned `BlockUUID` for the corresponding Module Entry. |
| `+0x10` | 8 | `BaseAddr` | Module load address. |
| `+0x18` | 8 | `ModuleSize` | Module mapping size. |
| `+0x20` | 2 | `PathLen` | Path length (incl. null). |
| `+0x22` | 2 | `Reserved` | Zero. |
| `+0x24` | 4 | `Reserved2` | Zero. |
| `+0x28` | var | `Path` | UTF-8, pad8. Module path/name. |

After reading Block 1, a consumer can build: (1) a UUID→module-name map, (2) an address-range→module map for correlating Memory Regions to their owning library, and (3) a forward-reference table telling the parser which future blocks correspond to which modules.

### 5.4 Process Identity (0x0040)

An acquirer **MUST** emit a Process Identity block as Block 0 (Figure 6, PDF), the first capture-time block (or immediately after Import Provenance for imported files). The file header's `PID` identifies the process numerically, but PIDs are ephemeral and recycled; this block answers "what process is this?" without scanning the entire file. Importers **MAY** omit this block if the source format does not provide the information.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 4 | `PPID` | Parent process ID. 0 if unknown. |
| `+0x04` | 4 | `SessionID` | Session/login session ID. 0 if unknown. |
| `+0x08` | 8 | `StartTime` | Process start time (UTC, nanoseconds since Unix epoch). 0 if unknown. |
| `+0x10` | 2 | `ExePathLen` | Length of `ExePath` (incl. null). |
| `+0x12` | 2 | `CmdLineLen` | Length of `CmdLine` (incl. null). 0 if unavailable. |
| `+0x14` | 4 | `Reserved` | Zero. |
| `+0x18` | var | `ExePath` | UTF-8, pad8. Full executable path. |
| `+e` | var | `CmdLine` | UTF-8, pad8. `e = 0x18 + pad8(ExePathLen)`. |

### 5.5 Related Dump (0x0041)

An acquirer **MAY** emit one or more Related Dump blocks to record relationships between concurrently captured processes.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 16 | `RelatedDumpUUID` | `DumpUUID` of the related MSL file. |
| `+0x10` | 4 | `RelatedPID` | PID of the related process. 0 if unknown. |
| `+0x14` | 2 | `Relationship` | `0x0000`=Unknown, `0x0001`=Parent, `0x0002`=Child, `0x0003`=SharedMemory, `0x0004`=IPC peer, `0x0005`=Thread group. `0xFFFF`=Other. |
| `+0x16` | 2 | `Reserved` | Zero. |

### 5.6 Key Hint (0x0020)

A Key Hint block (Figure 7, PDF) annotates the location and type of cryptographic key material within a captured memory region. This bridges live and dead forensics: an acquirer that instruments KDFs (e.g., via Frida/friTap) can record where key material resides. Key Hints are **OPTIONAL**; their presence is indicated by `CryptoHints` (CapBitmap bit 10) and `HasKeyHints` (block flag bit 3).

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 16 | `RegionUUID` | `BlockUUID` of the Memory Region containing the key material. |
| `+0x10` | 8 | `RegionOffset` | Byte offset within the region's `PageData`. |
| `+0x18` | 4 | `KeyLen` | Length of key material in bytes. 0 if unknown. |
| `+0x1C` | 2 | `KeyType` | Key type code (see below). |
| `+0x1E` | 2 | `Protocol` | Protocol code (see below). |
| `+0x20` | 1 | `Confidence` | `0x00`=Speculative, `0x01`=Heuristic, `0x02`=Confirmed. |
| `+0x21` | 1 | `KeyState` | `0x00`=Unknown, `0x01`=Active at capture, `0x02`=Expired/zeroed. |
| `+0x22` | 2 | `Reserved` | Zero. |
| `+0x24` | 4 | `NoteLen` | Note length (incl. null). 0 if none. |
| `+0x28` | 4 | `Reserved2` | Zero. |
| `+0x2C` | var | `Note` | UTF-8, pad8. Free-form provenance. |

**Key type codes:** `0x0000`=Unknown, `0x0001`=Pre-Master Secret, `0x0002`=Master Secret, `0x0003`=Session Key (symmetric), `0x0004`=Handshake Secret, `0x0005`=Application Traffic Secret, `0x0006`=RSA Private Key, `0x0007`=ECDH Private Key, `0x0008`=IKE SA Key, `0x0009`=ESP/AH Key, `0x000A`=SSH Session Key, `0x000B`=WireGuard Key. `0xFFFF`=Other.

**Protocol codes:** `0x0000`=Unknown, `0x0001`=TLS 1.2, `0x0002`=TLS 1.3, `0x0003`=DTLS 1.2, `0x0004`=DTLS 1.3, `0x0005`=QUIC, `0x0006`=IKEv2/IPsec, `0x0007`=SSH, `0x0008`=WireGuard, `0x0009`=PQ-TLS (hybrid). `0xFFFF`=Other.

**Confidence levels.** The `Confidence` field distinguishes three provenance qualities. **Speculative (`0x00`):** the acquirer knows the region belongs to a cryptographic library but has not located specific keys — useful as a search hint. **Heuristic (`0x01`):** a pattern-matching scan identified candidate key material — may produce false positives. **Confirmed (`0x02`):** the acquirer instrumented the KDF (e.g., via Frida/friTap) and captured the exact derivation event — ground truth with precise offset and length. A dump acquired with friTap can carry forward its instrumentation knowledge, so a dead-forensics tool (e.g., TLSKeyHunter) can skip discovery and directly extract confirmed keys.

---

## 6. Three-State Virtual Address Map

The `PageStateMap` in each Memory Region block encodes one of three states per page using 2 bits. See Figure 8 (PDF) for an example 12-page map.

| Bits | State | Meaning | PageData |
|------|-------|---------|----------|
| `00` | Captured | Read OK; stored. | PageSize bytes |
| `01` | Failed | Mapped but unreadable. | 0 |
| `10` | Unmapped | Not present at read time (TOCTOU). | 0 |
| `11` | *Reserved* | Treat as Failed. | 0 |

**Why Unmapped exists within a region.** Acquisition is not atomic: regions are enumerated first, then pages are read. Between enumeration and read, the process may unmap pages — a Time-of-Check to Time-of-Use (TOCTOU) race condition, where the state observed during enumeration differs from the state encountered during the subsequent read. `Unmapped` records this: the page was in the region at enumeration but absent at read time — distinct from `Failed` (mapped but unreadable) and from never appearing at all.

**Reconstruction algorithm.** Compute `PageSize = 2^PageSizeLog2`, then iterate `PageStateMap` 2 bits at a time with a cursor into `PageData`. For `00`: copy `PageSize` bytes, advance cursor. For `01`/`10`: record state, do not advance cursor.

---

## 7. Block Cross-Referencing

Blocks form a graph of relationships enabling consumers to navigate from discovered material back to its source region and the module whose allocator produced it. The model provides two complementary layers:

**Layer 1: `ParentUUID` (Common Block Header).** Establishes "belongs-to" hierarchy. Any consumer can traverse it without understanding payloads.

**Layer 2: Payload-embedded UUIDs.** For richer relationships. A Key Hint block contains a `RegionUUID` identifying the Memory Region where cryptographic key material was found. Requires type-aware parsing.

Figure 9 (PDF) illustrates both layers for a concrete scenario: two Module Entry blocks (`ntdll.dll`, `kernel32.dll`) reference their Module List Index via `ParentUUID` (solid arrows). A Heap Region references its owning module. A Key Hint block references its source region via a payload-embedded `RegionUUID` (dashed arrow), enabling an analyst to trace cryptographic key material back to the heap that contains it.

---

## 8. Capability Bitmap

The `CapBitmap` (8 bytes, 64 bits) documents which metadata categories were captured.

| Bit | Name | Description |
|-----|------|-------------|
| 0 | MemoryRegions | Type `0x0001` present. |
| 1 | ModuleList | Types `0x0010`/`0x0002` present. |
| 2 | ThreadContexts | Type `0x0011`. |
| 3 | FileDescriptors | Type `0x0012`. |
| 4 | NetworkState | Type `0x0013`. |
| 5 | EnvironmentVars | Type `0x0014`. |
| 6 | SharedMemory | IPC identifiers. |
| 7 | SecurityContext | Type `0x0015`. |
| 8 | ProcessIdentity | Type `0x0040` present. |
| 9 | RelatedDumps | Type `0x0041` present. |
| 10 | CryptoHints | Key Hint blocks (`0x0020`) present. |
| 11–63 | Reserved | Zero. |

An acquirer **MUST** set exactly those bits corresponding to successfully captured categories.

---

## 9. Raw Dump Import

### 9.1 Import Provenance Block (0x0030)

An importer **MUST** emit exactly one Import Provenance block as Block 0.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 2 | `SourceFormat` | See codes below. |
| `+0x02` | 2 | `Reserved` | Zero. |
| `+0x04` | 4 | `ToolNameLen` | Tool name length (incl. null). |
| `+0x08` | 8 | `ImportTime` | Import time (nanoseconds since Unix epoch). |
| `+0x10` | 8 | `OrigFileSize` | Original file size. 0 if unknown. |
| `+0x18` | 4 | `NoteLen` | Note length (incl. null). 0 if none. |
| `+0x1C` | 4 | `Reserved2` | Zero. |
| `+0x20` | var | `ToolName` | UTF-8, pad8. |
| `+t` | var | `Note` | UTF-8, pad8. |

**Source format codes:** `0x0000`=Unknown, `0x0001`=Raw byte stream, `0x0002`=ELF core dump, `0x0003`=Windows Minidump, `0x0004`=macOS core dump, `0x0005`=ProcDump. `0xFFFF`=Other.

### 9.2 Import Procedure

1. **File header:** Set `Flags` bit 0 (`Imported`). Set `OSType`/`ArchType`/`PID` if known, else `0xFFFF`/`0xFFFF`/0.
2. **Block 0:** Import Provenance (`0x0030`).
3. **Memory Regions:** For raw streams: single region, `BaseAddr`=0, all Captured. For ELF cores: parse program headers. For Minidumps: parse `MINIDUMP_MEMORY_LIST`.
4. **Modules:** Extract from source if available.
5. **Hash chain and EoC:** Block 0's PrevHash = BLAKE3(File Header); emit EoC as final block.

---

## 10. Parsing Walkthrough

1. **File header.** Read 9 bytes. Verify magic. `Endianness` at `0x08`. `HeaderSize` at `0x09`. Read remaining header in determined byte order.
2. **Blocks.** Start at `HeaderSize`. Read 80B Common Block Header, verify block Magic (`0x4D534C43`), parse or skip per `BlockType`/`BlockLength`. Continue until fewer than 80 bytes remain or the next 4 bytes do not match the block magic.
3. **Integrity chain** (optional but recommended). Compute BLAKE3(header), verify against Block 0's `PrevHash`. For each block i ≥ 1, compute BLAKE3(block_{i-1}) and compare against block i's `PrevHash`.
4. **EoC verification.** If present, compute BLAKE3 over all file bytes preceding it and verify against `FileHash`.
5. **Index.** Build `BlockUUID`→offset and `ParentUUID`→children maps.
6. **Import check.** `Flags` bit 0 set? Read Import Provenance (`0x0030`).
7. **Payloads.** Regions via PageStateMap. Modules via pad8 offsets.

---

## 11. Worked Example

A complete Module Entry block for `ntdll.dll` version `10.0.22621.1` at `0x7FFDD4D00000`, little-endian.

**Sizes:** Path=30B (pad8=32). Version=13B (pad8=16). Payload: 8+8+2+2+4+32+16+32+4+4+384 = 496B. Block: 80+496 = 576 (`0x0240`).

| Off | Field | Hex | Value |
|-----|-------|-----|-------|
| *— Header (80B) —* | | | |
| `0x00` | Magic | `4D 53 4C 43` | MSLC |
| `0x04` | BlockType | `02 00` | Module Entry |
| `0x08` | BlockLength | `40 02 00 00` | 576 |
| `0x0C` | PayloadVersion | `01 00` | 1 |
| `0x0E` | Reserved | `00 00` | |
| `0x10` | BlockUUID | (16B) | UUIDv4 (matches ModuleUUID from manifest) |
| `0x20` | ParentUUID | (16B) | Module List UUID |
| `0x30` | PrevHash | (32B) | BLAKE3 of prev |
| *— Payload (496B) —* | | | |
| `0x50` | BaseAddr | `00 00 D0 D4 FD 7F 00 00` | `0x7FFDD4D00000` |
| `0x58` | ModuleSize | `00 00 20 00 00 00 00 00` | 2 MiB |
| `0x60` | PathLen | `1E 00` | 30 |
| `0x62` | VersionLen | `0D 00` | 13 |
| `0x68` | Path (32B) | `43 3A 5C 57...` | ntdll.dll |
| `0x88` | Version (16B) | `31 30 2E 30...` | 10.0.22621.1 |
| `0x98` | DiskHash (32B) | ... | BLAKE3 of binary |
| `0xB8` | BlobLen | `80 01 00 00` | 384 |
| `0xC0` | NativeBlob (384B) | ... | LDR_DATA_TABLE_ENTRY |

---

## 12. Conformance

### 12.1 Producer

A conformant producer **MUST:** (1) write a valid header with `Magic`, `Endianness` (default `0x01`), `HeaderSize`, `Version`; (2) use byte order per `Endianness`; (3) generate UUIDv4 in RFC 4122 network byte order; (4) compute BLAKE3 `PrevHash`: Block 0 hashes the header, subsequent blocks hash the preceding block over raw on-disk bytes; (5) set reserved fields to zero; (6) pad8 all variable fields; (7) never modify written blocks or the file header after subsequent data is written; (8) set `CapBitmap` accurately; (9) if importing: set `Flags` bit 0 and emit Import Provenance (`0x0030`) as Block 0; (10) set `PayloadVersion` to 1 for all payload layouts defined in this specification version; (11) set `CompAlgo` bits (1–2) to `00` when the `Compressed` flag is not set; (12) split memory regions exceeding 2³²−81 bytes into multiple blocks with the `Continuation` flag (Section 5.1); (13) write 32 zero bytes into `DiskHash` when the on-disk binary is unavailable; (14) reject `PageSizeLog2` values outside [10, 40].

A conformant acquirer (live capture) **MUST** emit a Process Identity block (`0x0040`) as Block 0 and a Module List Index (`0x0010`) as Block 1 with pre-assigned UUIDs for all enumerated modules. An importer **MAY** omit these if the source format does not provide the information.

A conformant producer **SHOULD** emit an End-of-Capture block (type `0x0FFF`, Section 4.5) as the final capture-time block to mark the acquisition as complete.

### 12.2 Consumer

A conformant consumer **MUST:** (1) reject files with invalid file magic or `Endianness`; (2) use `HeaderSize` to locate Block 0; (3) skip unknown block types via `BlockLength`; (4) detect end-of-blocks when fewer than 80 bytes remain or the next 4 bytes are not `0x4D534C43`; (5) ignore reserved fields; (6) reject block type `0x0000` as invalid; (7) skip blocks with an unrecognized `PayloadVersion` for a known `BlockType` via `BlockLength`; (8) treat an all-zero `DiskHash` as "hash not available"; (9) ignore `CompAlgo` bits when the `Compressed` flag is not set; (10) reject `PageSizeLog2` values outside [10, 40].

A conformant consumer **SHOULD:** (1) verify the BLAKE3 chain from the file header through all blocks; (2) if an EoC block is present, verify `FileHash` against the computed digest of the file up to the EoC block; (3) check `CapBitmap` before searching for specific block types. If no EoC block is present, the consumer **SHOULD** verify the file against an externally stored digest when available.

---

## References

1. S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels," RFC 2119, 1997.
2. P. Leach, M. Mealling, R. Salz, "A Universally Unique IDentifier (UUID) URN Namespace," RFC 4122, 2005.
3. J. O'Connor et al., "BLAKE3: One function, fast everywhere," 2020.
4. TIS Committee, "ELF Specification," v1.2, 1995.
