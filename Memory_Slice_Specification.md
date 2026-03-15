# Memory Slice (.msl) — Binary Format Specification

**Version:** draft-2026-03  
**Status:** Working Draft

---

## Abstract

Memory Slice (`.msl`) is a self-describing, block-based binary format for capturing the forensic state of a single operating system process. It records both the virtual address space (with per-page acquisition status) and transient OS-queryable metadata that exists only while the process is alive. This document specifies the binary layout: file header, block architecture, integrity chain, capture-time payloads, cross-referencing, capability bitmap, block index table, and raw dump import mechanism.

This specification accompanies the research paper *Memory Slice: A Process-Centric Dump Format Enabling Differential Structure Discovery in Memory Forensics*. The differential analysis algorithm, MemDiver framework, and evaluation are outside this document's scope.

---

## Table of Contents

1. [Scope and Conventions](#1-scope-and-conventions)
2. [Format Overview](#2-format-overview)
3. [File Header](#3-file-header)
4. [Block Architecture](#4-block-architecture)
5. [Capture-Time Payloads](#5-capture-time-payloads)
6. [Three-State Virtual Address Map](#6-three-state-virtual-address-map)
7. [Block Cross-Referencing](#7-block-cross-referencing)
8. [Capability Bitmap](#8-capability-bitmap)
9. [Block Index Table (0x1000)](#9-block-index-table-0x1000)
10. [Raw Dump Import](#10-raw-dump-import)
11. [Parsing Walkthrough](#11-parsing-walkthrough)
12. [Worked Example](#12-worked-example)
13. [Conformance](#13-conformance)

---

## 1. Scope and Conventions

### 1.1 Scope

This document defines the binary wire format of Memory Slice (`.msl`) files. It does *not* specify acquisition procedures or analysis algorithms.

### 1.2 Normative Language

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, "RECOMMENDED", **MAY**, and **OPTIONAL** are per RFC 2119.

### 1.3 Encoding Conventions

- The file header's `Endianness` byte at offset `0x08` determines the byte order for all multi-byte integers throughout the file. `0x01` = little-endian (default); `0x02` = big-endian. Producers **SHOULD** use little-endian unless the target platform is natively big-endian. Because this is a single `uint8`, it has no endianness ambiguity (Section 3.1).
- Strings are UTF-8, null-terminated, padded to **8-byte** boundaries with zero bytes. `pad8(n) = ⌈n/8⌉ × 8`. All padding bytes **MUST** be initialized to `0x00`.
- Variable-length fields (`PageStateMap`, `NativeBlob`) are padded to 8-byte boundaries with zero bytes.
- UUIDs **MUST** be version 4 (random) per RFC 4122, stored as 16 raw bytes in RFC 4122 network byte order (big-endian sub-fields), regardless of the file's `Endianness`. See Section 1.4.
- Hashes use BLAKE3 with 32-byte output (Section 4.4).
- Timestamps: unsigned 64-bit nanoseconds since Unix epoch.
- All `Reserved` fields **MUST** be zero (producers) and **MUST** be ignored (consumers).

### 1.4 UUID Requirements

All UUID fields (`DumpUUID`, `BlockUUID`, `ParentUUID`, payload UUIDs) **MUST** be version 4 (random) per RFC 4122. The 4-bit version field (bits 48–51) **MUST** be `0100`; the 2-bit variant (bits 64–65) **MUST** be `10`. UUIDs are always in RFC 4122 binary layout regardless of file endianness.

> **Implementation guidance: UUID generation performance**
> UUID generation can bottleneck high-throughput acquisition. Producers need not use a CSRNG; UUIDs are identifiers, not security tokens. A thread-local fast PRNG such as `xoshiro256++` or `PCG64`, seeded once from OS entropy, provides sufficient uniqueness (~2⁻⁶¹ collision probability per pair).

### 1.5 Terminology

- **Producer** — Software that creates or appends blocks.
- **Consumer** — Software that reads an MSL file.
- **Acquirer** — A producer capturing live process state (types `0x0000`–`0x0FFF`).
- **Importer** — A producer converting a raw dump into MSL (Section 10).
- **Block** — Fixed header + variable payload.
- **Payload** — Block-type-specific data after the header.

---

## 2. Format Overview

An MSL file is a linear byte stream: a **file header** (64 bytes in v1.0) followed by **typed, length-prefixed blocks**. No inter-block gaps. `HeaderSize` tells the consumer where blocks begin, enabling future header extensions.

```
┌──────────────┬──────────────┬──────────────┬─────┬──────────────┐
│  File Header │   Block 0    │   Block 1    │ ... │  Block N-1   │
│ HeaderSize B │  Hdr+Payload │  Hdr+Payload │     │  Hdr+Payload │
│  "MEMSLICE"  │PrevHash=B3(H)│PrevHash=B3(0)│     │PrevHash=B3(..)│
└──────────────┴──────────────┴──────────────┴─────┴──────────────┘
0x00         HeaderSize                                         EOF
```

Block 0's `PrevHash` = BLAKE3(File Header), anchoring the integrity chain. Each subsequent block hashes its predecessor, so modifying any block invalidates all subsequent hashes. Consumers detect end-of-file when fewer than 80 bytes remain or the next 4 bytes do not match the block magic (`0x4D534C43`).

> **Integrity of the last block**
> The forward-linked BLAKE3 chain protects every block except the last one. To close the integrity loop, acquirers **SHOULD** emit an End-of-Capture (EoC) block (type `0x0FFF`, Section 4.5) as the final capture-time block.

### 2.1 Design Principles

1. **Integrity Verification (Append-Only Policy, Anchored Hash Chain).** Producers treat all written blocks as append-only. The BLAKE3 chain enables consumers to detect accidental corruption or post-hoc modification. See scoping note below.
2. **Epistemic Honesty (Three-State Pages).** Captured vs. Failed vs. Unmapped.
3. **Self-Describing.** Endianness, version, header size, OS, arch, PID, capabilities.
4. **Dual-Layer OS Abstraction.** Normalized fields + OS-native opaque blob.

> **Scope of the integrity guarantee**
>
> The hash chain provides *tamper detection*, not *tamper resistance*. Because the chain uses an unkeyed hash function, any party with write access can modify a block and recompute all subsequent hashes. The chain protects against **accidental corruption** (bit-rot, truncation, transfer errors) and detects **naive modification** (altering a block without updating the chain). It does *not* protect against an adversary who deliberately rewrites the file.
>
> For scenarios requiring tamper evidence admissible in legal or regulatory contexts, producers **SHOULD** complement the in-file hash chain with external mechanisms such as a digital signature (e.g., Ed25519) over the EoC `FileHash`, a timestamped hash commitment to a trusted third party (RFC 3161), or write-once storage media. In the absence of such mechanisms, the in-file hash chain alone **MUST NOT** be represented as providing forensic-grade tamper evidence.

> **No block count in the header**
> The header has no block count. Appending blocks would require mutating it, violating append-only integrity. Consumers read blocks sequentially until fewer than 80 bytes remain or the next 4 bytes do not match the block magic.

---

## 3. File Header

The header (64 bytes in v1.0) places the single-byte `Endianness` at offset `0x08` and `HeaderSize` at `0x09`. A parser reads these two `uint8` values—which have no byte-order ambiguity—before encountering any multi-byte field.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `0x00` | 8 | `Magic` | `0x4D454D534C494345` ("MEMSLICE"). Endianness-independent. |
| `0x08` | 1 | `Endianness` | `0x01`=LE, `0x02`=BE. Invalid values **MUST** cause rejection. |
| `0x09` | 1 | `HeaderSize` | Header size in bytes (`uint8`). v1.0: **MUST** be 64 (`0x40`). |
| `0x0A` | 2 | `Version` | `uint16` read per `Endianness`. Major in high byte, minor in low byte. v1.0: `0x0100` (=256). |
| `0x0C` | 4 | `Flags` | Bit 0: `Imported`. Bit 1: `CryptoHints` (Key Hint blocks `0x0020` present). Bits 2–31: reserved, zero. |
| `0x10` | 8 | `CapBitmap` | Capability bitmap (Section 8). |
| `0x18` | 16 | `DumpUUID` | UUIDv4 for this dump. |
| `0x28` | 8 | `Timestamp` | Acquisition start (UTC wall-clock, ns since epoch). |
| `0x30` | 2 | `OSType` | Target OS (Table 2a). |
| `0x32` | 2 | `ArchType` | Target CPU (Table 2b). |
| `0x34` | 4 | `PID` | Process ID at acquisition. |
| `0x38` | 1 | `ClockSource` | Clock used for timestamps. `0x00`=Unknown, `0x01`=`CLOCK_REALTIME`, `0x02`=`CLOCK_MONOTONIC_RAW`, `0x03`=`QueryPerformanceCounter`, `0x04`=`mach_absolute_time`. `0x05`–`0xFE`: reserved. `0xFF`=Other. Producers **SHOULD** use a monotonic source for per-region timestamps; `Timestamp` **SHOULD** be UTC wall-clock. |
| `0x39` | 7 | `Reserved` | **MUST** be zero. |

**Size:** 8+1+1+2+4+8+16+8+2+2+4+1+7 = 64.

### 3.1 Endianness Bootstrapping

Uses the ELF approach (`e_ident[EI_DATA]`): a single byte read identically regardless of host byte order.

**Parse sequence:** (1) Read 8-byte magic. (2) Read `Endianness` at `0x08`. (3) Read `HeaderSize` at `0x09`. (4) All subsequent multi-byte reads use the determined order.

Memory content within `PageData` is stored in the *target architecture's* native order; `Endianness` governs only format-level structural integers.

### 3.2 Version Compatibility

Unknown major version: **SHOULD** reject. Unknown minor of known major: **MAY** parse. Always use `HeaderSize` to locate Block 0.

### 3.3 Platform Codes

**OS type codes (`OSType`):**

| Code | OS |
|------|----|
| `0x0000` | Windows |
| `0x0001` | Linux |
| `0x0002` | macOS |
| `0x0003` | Android |
| `0x0004` | iOS / iPadOS |
| `0x0005` | FreeBSD |
| `0x0006` | NetBSD |
| `0x0007` | OpenBSD |
| `0x0008` | QNX |
| `0x0009` | Fuchsia |
| `0x000A`–`0x00FF` | *Reserved* |
| `0x0100`–`0xFFFE` | *Vendor* |
| `0xFFFF` | Unknown |

**Architecture codes (`ArchType`):**

| Code | Architecture |
|------|-------------|
| `0x0000` | x86 (IA-32) |
| `0x0001` | x86_64 (AMD64) |
| `0x0002` | ARM64 (AArch64) |
| `0x0003` | ARM32 (AArch32) |
| `0x0004` | MIPS32 |
| `0x0005` | MIPS64 |
| `0x0006` | RISC-V RV32 |
| `0x0007` | RISC-V RV64 |
| `0x0008` | PPC32 |
| `0x0009` | PPC64 |
| `0x000A` | s390x |
| `0x000B` | LoongArch64 |
| `0x000C`–`0x00FF` | *Reserved* |
| `0x0100`–`0xFFFE` | *Vendor* |
| `0xFFFF` | Unknown |

---

## 4. Block Architecture

Every block consists of a **fixed 80-byte common header** followed by a **variable-length payload**. A consumer that does not recognize a block's type reads `BlockLength` and skips `(BlockLength − 80)` bytes to reach the next block.

### 4.1 Common Block Header (80 bytes)

All fields ≥ 8 bytes are 8-byte aligned, enabling zero-copy casting.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `0x00` | 4 | `Magic` | `0x4D534C43` ("MSLC"). |
| `0x04` | 2 | `BlockType` | Payload selector (Section 4.3). |
| `0x06` | 2 | `Flags` | Per-block flags (Section 4.2). |
| `0x08` | 4 | `BlockLength` | Total size (hdr+payload). ≥ 80. |
| `0x0C` | 2 | `PayloadVersion` | Payload layout version. Default: `0x0001`. Consumers **SHOULD** skip unknown versions via `BlockLength`. |
| `0x0E` | 2 | `Reserved` | **MUST** be zero. |
| `0x10` | 16 | `BlockUUID` | UUIDv4 identifier. 8-byte aligned. |
| `0x20` | 16 | `ParentUUID` | Parent UUID or zeros. 8-byte aligned. |
| `0x30` | 32 | `PrevHash` | BLAKE3 of preceding element (Section 4.4). 8-byte aligned. |
| `0x50` | var | `Payload` | `BlockLength − 80` bytes. 8-byte aligned. |

**Verification:** 4+2+2+4+2+2+16+16+32 = 80. Payload starts at `0x50`.

### 4.2 Block Flags

| Bit(s) | Name | Description |
|--------|------|-------------|
| 0 | `Compressed` | Algorithm in bits 1–2. |
| 1–2 | `CompAlgo` | `00`=none, `01`=zstd, `10`=lz4, `11`=reserved. |
| 3 | `HasKeyHints` | One or more Key Hint blocks (`0x0020`) reference this block. |
| 4 | `Optional` | **MAY** skip if unrecognized. |
| 5 | `HasChildren` | Referenced via `ParentUUID`. |
| 6 | `Continuation` | This block is a continuation fragment of a larger logical unit. `ParentUUID` references the first fragment. |
| 7–15 | `Reserved` | Zero. |

**CompAlgo semantics.** If `Compressed` (bit 0) is not set, a consumer **MUST** ignore bits 1–2 and treat the payload as uncompressed. A producer **MUST** set bits 1–2 to `00` when `Compressed` is not set.

### 4.3 Block Type Registry

| Range | Namespace | Writer | Examples |
|-------|-----------|--------|----------|
| `0x0000`–`0x0FFF` | Capture-Time | Acquirer/Importer | Regions, modules, threads, keys, import provenance |
| `0x1000`–`0x1FFF` | Structural | Analysis tool | Index, VAS map, classification, pointer graph |
| `0x2000`–`0x2FFF` | Semantic | Analysis tool | Structure candidates, annotations, signatures |

**Defined block types:**

| Type | Name | Description |
|------|------|-------------|
| `0x0000` | *Invalid* | Reserved. **MUST NOT** appear in a valid file. |
| `0x0001` | Memory Region | Per-page memory (Section 5.1). |
| `0x0002` | Module Entry | Module metadata (Section 5.2). |
| `0x0010` | Module List Index | Groups Module Entries. |
| `0x0011` | Thread Context | Register state. |
| `0x0012` | File Descriptor | Open handle. |
| `0x0013` | Network Connection | Socket attribution. |
| `0x0014` | Environment Block | Env vars. |
| `0x0015` | Security Token | Credentials. |
| `0x0020` | Key Hint | Cryptographic key location annotation (Section 5.5). |
| `0x0030` | Import Provenance | Raw dump metadata (Section 10). |
| `0x0040` | Process Identity | Executable path, command line, PPID (Section 5.3). |
| `0x0041` | Related Dump | Cross-file reference (Section 5.4). |
| `0x0FFF` | End-of-Capture | Whole-file integrity seal (Section 4.5). |
| `0x1000` | Block Index Table | UUID→offset mapping for random access (Section 9). |
| `0x1001` | VAS Map | Reconstructed address space. |
| `0x1002` | Region Classification | Stability tags. |
| `0x1003` | Pointer Graph | Pointer relationships. |
| `0x2001` | Structure Candidate | Discovered type. |
| `0x2002` | Analyst Annotation | Free-form note. |
| `0x2003` | Diff Result | Differential analysis. |
| `0x2004` | Scan Signature | Byte pattern export. |

### 4.4 Integrity Chain (PrevHash)

The chain uses BLAKE3 with 32-byte (256-bit) output. BLAKE3 was selected for its throughput — typically 3–4× faster than SHA-256 on modern CPUs with SIMD support — which minimizes acquisition overhead. Its collision resistance (128-bit birthday bound) is equivalent to SHA-256; the choice is motivated by performance, not security margin.

- **Block 0:** `PrevHash = BLAKE3(File Header, all HeaderSize bytes)`.
- **Block i (i ≥ 1):** `PrevHash = BLAKE3(Block_{i-1}, all BlockLength bytes)`.

**Wire-format hashing.** The `PrevHash` is always computed over the *raw on-disk bytes* of the preceding element. If a block's payload is compressed, the hash covers the compressed wire format, not the decompressed content.

### 4.5 End-of-Capture Block (0x0FFF)

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 32 | `FileHash` | BLAKE3 digest of all bytes from offset 0 through the last byte before this EoC block. |
| `+0x20` | 8 | `AcqEnd` | Acquisition end time (UTC, ns since epoch). |
| `+0x28` | 8 | `Reserved` | **MUST** be zero. |

**Integrity semantics.** If present, verify in two steps: (1) verify the `PrevHash` chain through all blocks including EoC, (2) compute BLAKE3 over `[0..EoC offset−1]` and compare against `FileHash`.

> **Implementation guidance: streaming FileHash computation**
> Producers **SHOULD** maintain a running BLAKE3 hasher state during acquisition, feeding each written byte into the incremental hasher. When writing the EoC block, the producer finalizes the hasher to obtain `FileHash` without a second pass over the file.

---

## 5. Capture-Time Payloads

Payload data begins at byte `0x50` within each block. All offsets below are relative to the payload start.

### 5.1 Memory Region (0x0001)

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 8 | `BaseAddr` | Virtual address of the region's first byte. |
| `+0x08` | 8 | `RegionSize` | Region size in bytes. **MUST** be a multiple of `2^PageSizeLog2`. |
| `+0x10` | 1 | `Protection` | Bit 0=R, 1=W, 2=X, 3=Guard, 4=CopyOnWrite. Bits 5–7 reserved. |
| `+0x11` | 1 | `RegionType` | `0x00`=Unknown, `01`=Heap, `02`=Stack, `03`=Image, `04`=MappedFile, `05`=Anonymous, `06`=SharedMem, `FF`=Other. |
| `+0x12` | 1 | `PageSizeLog2` | Power-of-two exponent: actual page size is `2^PageSizeLog2` bytes. Value 12 = 4 KiB; 21 = 2 MiB; 30 = 1 GiB. **MUST** be in range [10, 40]; values outside this range **MUST** cause rejection. |
| `+0x13` | 1 | `Reserved1` | **MUST** be zero. |
| `+0x14` | 4 | `Reserved2` | **MUST** be zero. |
| `+0x18` | 8 | `Timestamp` | Time this region was acquired (UTC, ns since epoch). |
| `+0x20` | var | `PageStateMap` | 2 bits per page (Section 6). Padded to 8-byte boundary. |
| `+m` | var | `PageData` | Concatenated bytes of Captured pages only. |

**PageStateMap size.** Let `PageSize = 2^PageSizeLog2` and `P = RegionSize >> PageSizeLog2` (the page count). The map requires `P × 2` bits:

```
map_bytes = pad8((P + 3) / 4)    where pad8(n) = (n + 7) & ~7
```

`PageData` immediately follows at offset `0x20 + map_bytes`.

> **Regions exceeding BlockLength capacity**
>
> `BlockLength` is a `uint32`, limiting any single block to ~4.29 GiB. Contiguous virtual address ranges exceeding this limit (e.g., large JVM heaps, database shared buffers) **MUST** be split into multiple Memory Region blocks. Each **continuation block** covers a sub-range at the appropriate `BaseAddr` and **MUST** set the `Continuation` flag (bit 6) and `ParentUUID` to the `BlockUUID` of the first fragment. The first fragment sets `HasChildren` (bit 5). Consumers reassemble by collecting all blocks with the same `ParentUUID`, sorting on `BaseAddr`, and concatenating.

### 5.2 Module Entry (0x0002)

Each loaded module is stored as a separate block whose `ParentUUID` **MUST** reference the Module List Index (type `0x0010`).

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

**DiskHash unavailability.** If the on-disk binary is inaccessible (deleted file, `memfd`, fileless malware, insufficient permissions), the acquirer **MUST** write 32 zero bytes. A consumer **MUST** treat all-zero `DiskHash` as "hash not available."

> **NativeBlob expected contents by OS**
> - **Windows (`0x0000`):** Serialized `LDR_DATA_TABLE_ENTRY`.
> - **Linux (`0x0001`):** Corresponding `/proc/pid/maps` (or `smaps`) line, UTF-8, null-terminated.
> - **macOS (`0x0002`):** Serialized `dyld_image_info` structure.
> - **Android (`0x0003`):** Same as Linux, plus ART-specific metadata if available.

### 5.3 Process Identity (0x0040)

An acquirer **MUST** emit a Process Identity block as the first capture-time block (or immediately after Import Provenance for imported files). PIDs are ephemeral and recycled; this block answers "what process is this?" without scanning the entire file. Importers **MAY** omit this block if the source format does not provide the information.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 4 | `PPID` | Parent process ID. 0 if unknown. |
| `+0x04` | 4 | `SessionID` | Session/login session ID. 0 if unknown. |
| `+0x08` | 8 | `StartTime` | Process start time (UTC, ns since epoch). 0 if unknown. |
| `+0x10` | 2 | `ExePathLen` | Length of `ExePath` (incl. null). |
| `+0x12` | 2 | `CmdLineLen` | Length of `CmdLine` (incl. null). 0 if unavailable. |
| `+0x14` | 4 | `Reserved` | Zero. |
| `+0x18` | var | `ExePath` | UTF-8, pad8. Full executable path. |
| `+e` | var | `CmdLine` | UTF-8, pad8. `e = 0x18 + pad8(ExePathLen)`. |

### 5.4 Related Dump (0x0041)

An acquirer **MAY** emit one or more Related Dump blocks to record relationships between concurrently captured processes.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 16 | `RelatedDumpUUID` | `DumpUUID` of the related MSL file. |
| `+0x10` | 4 | `RelatedPID` | PID of the related process. 0 if unknown. |
| `+0x14` | 2 | `Relationship` | `0x0000`=Unknown, `0x0001`=Parent, `0x0002`=Child, `0x0003`=SharedMemory, `0x0004`=IPC peer, `0x0005`=Thread group. `0xFFFF`=Other. |
| `+0x16` | 2 | `Reserved` | Zero. |

### 5.5 Key Hint (0x0020)

A Key Hint block annotates the location and type of cryptographic key material within a captured memory region. This bridges live and dead forensics: an acquirer that instruments key derivation functions at capture time can record where key material resides, so downstream analysis tools need not rediscover it. Key Hints are **OPTIONAL**; their presence is indicated by `CryptoHints` (Flags bit 1) in the header and `HasKeyHints` (bit 3) on the referenced Memory Region.

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

**Key type codes:**

| Code | Type |
|------|------|
| `0x0000` | Unknown |
| `0x0001` | Pre-Master Secret |
| `0x0002` | Master Secret |
| `0x0003` | Session Key (symmetric) |
| `0x0004` | Handshake Secret |
| `0x0005` | Application Traffic Secret |
| `0x0006` | RSA Private Key |
| `0x0007` | ECDH Private Key |
| `0x0008` | IKE SA Key |
| `0x0009` | ESP / AH Key |
| `0x000A` | SSH Session Key |
| `0x000B` | WireGuard Key |
| `0x000C`–`0xFFFE` | *Reserved* |
| `0xFFFF` | Other |

**Protocol codes:**

| Code | Protocol |
|------|----------|
| `0x0000` | Unknown |
| `0x0001` | TLS 1.2 |
| `0x0002` | TLS 1.3 |
| `0x0003` | DTLS 1.2 |
| `0x0004` | DTLS 1.3 |
| `0x0005` | QUIC |
| `0x0006` | IKEv2 / IPsec |
| `0x0007` | SSH |
| `0x0008` | WireGuard |
| `0x0009` | PQ-TLS (hybrid) |
| `0x000A`–`0xFFFE` | *Reserved* |
| `0xFFFF` | Other |

> **Confidence levels and the live–dead forensics bridge**
>
> - **Speculative (`0x00`):** The acquirer knows the region belongs to a cryptographic library (e.g., OpenSSL's `.bss`) but has not located specific keys. Useful as a search hint for downstream tools.
> - **Heuristic (`0x01`):** A pattern-matching scan (e.g., AES key schedule detection, entropy analysis) identified candidate key material. May produce false positives.
> - **Confirmed (`0x02`):** The acquirer instrumented the application's KDF and captured the exact key derivation event. This is ground truth: the offset and length are precise.
>
> A dump acquired with such a tool can carry forward its instrumentation knowledge into the MSL file, so a dead-forensics tool can skip discovery and directly extract confirmed keys.

---

## 6. Three-State Virtual Address Map

The `PageStateMap` in each Memory Region block encodes one of three states per page using 2 bits.

| Bits | State | Meaning | PageData |
|------|-------|---------|----------|
| `00` | Captured | Read OK; stored. | PageSize bytes |
| `01` | Failed | Mapped but unreadable. | 0 |
| `10` | Unmapped | Not present at read time (TOCTOU). | 0 |
| `11` | *Reserved* | Treat as Failed. | 0 |

> **Why Unmapped exists within a region**
> Acquisition is not atomic: regions are enumerated first, then pages are read. Between enumeration and read, the process may unmap pages (TOCTOU race). `Unmapped` records this: the page was in the region at enumeration but absent at read time.

**Reconstruction algorithm.** Compute `PageSize = 2^PageSizeLog2`, then iterate `PageStateMap` 2 bits at a time with a cursor into `PageData`. For `00`: copy `PageSize` bytes, advance cursor. For `01`/`10`: record state, do not advance cursor.

---

## 7. Block Cross-Referencing

**Layer 1: `ParentUUID` (common header).** Establishes "belongs-to" hierarchy. Any consumer can traverse it without understanding payloads.

**Layer 2: Payload-embedded UUIDs.** For richer relationships (e.g., a Structure Candidate referencing both source region and relevant module). Requires type-aware parsing.

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
| 10–63 | Reserved | Zero. |

---

## 9. Block Index Table (0x1000)

The block architecture is linear: the only way to locate a block by UUID is sequential scanning. For large dumps, the Block Index Table provides random access.

The index is a **Structural** block (type `0x1000`), written by analysis tools *after* acquisition — never by acquirers. This preserves append-only capture.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 4 | `EntryCount` | Number of index entries. |
| `+0x04` | 4 | `Reserved` | Zero. |
| `+0x08` | var | `Entries` | `EntryCount × 32` bytes each. |

**Index entry (32 bytes):**

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 16 | `BlockUUID` | The block's UUID. |
| `+0x10` | 8 | `FileOffset` | Byte offset from file start to the block's `Magic`. |
| `+0x18` | 2 | `BlockType` | The block's type code. |
| `+0x1A` | 2 | `PayloadVersion` | The block's payload version. |
| `+0x1C` | 4 | `BlockLength` | The block's total size. |

A consumer loads the index into a hash map (`BlockUUID` → entry) for O(1) lookup. The index **SHOULD** cover all blocks at the time it was written. If blocks are appended later, the consumer falls back to sequential scanning for blocks not in the index.

> **When to write the index**
> An analysis tool **SHOULD** write the Block Index Table as its first appended block after opening a file that lacks one. Interactive analysis tools benefit most; batch pipelines that read all blocks anyway may skip it.

---

## 10. Raw Dump Import

Raw process dumps (`/proc/pid/mem`, `ReadProcessMemory`, `gcore`, Minidumps) lack forensic metadata. MSL supports importing them.

### 10.1 Import Provenance Block (0x0030)

An importer **MUST** emit exactly one Import Provenance block as Block 0.

| Off | Size | Field | Description |
|-----|------|-------|-------------|
| `+0x00` | 2 | `SourceFormat` | See source format codes below. |
| `+0x02` | 2 | `Reserved` | Zero. |
| `+0x04` | 4 | `ToolNameLen` | Tool name length (incl. null). |
| `+0x08` | 8 | `ImportTime` | Import time (ns). |
| `+0x10` | 8 | `OrigFileSize` | Original file size. 0 if unknown. |
| `+0x18` | 4 | `NoteLen` | Note length (incl. null). 0 if none. |
| `+0x1C` | 4 | `Reserved2` | Zero. |
| `+0x20` | var | `ToolName` | UTF-8, pad8. |
| `+t` | var | `Note` | UTF-8, pad8. |

**Source format codes:**

| Code | Format |
|------|--------|
| `0x0000` | Unknown |
| `0x0001` | Raw byte stream |
| `0x0002` | ELF core dump |
| `0x0003` | Windows Minidump |
| `0x0004` | macOS core dump |
| `0x0005` | ProcDump |
| `0xFFFF` | Other |

### 10.2 Import Procedure

1. **File header:** Set `Flags` bit 0 (`Imported`). Set `OSType`/`ArchType`/`PID` if known, else `0xFFFF`/`0xFFFF`/0.
2. **Block 0:** Import Provenance (`0x0030`).
3. **Memory Regions:** For raw streams: single region, `BaseAddr`=0, all Captured. For ELF cores: parse program headers. For Minidumps: parse `MINIDUMP_MEMORY_LIST`.
4. **Modules:** Extract from source if available.
5. **Hash chain and EoC:** Block 0's PrevHash = BLAKE3(File Header); emit EoC as final block.

---

## 11. Parsing Walkthrough

1. **File header.** Read 9 bytes. Verify magic. `Endianness` at `0x08`. `HeaderSize` at `0x09`. Read remaining header.
2. **Blocks.** Start at `HeaderSize`. Read 80B header, verify block Magic, parse or skip per `BlockType`/`BlockLength`.
3. **Integrity chain** (optional but recommended). Compute BLAKE3(header), verify against Block 0's `PrevHash`. Chain through all blocks.
4. **EoC verification.** If present, verify `FileHash`.
5. **Index.** `BlockUUID`→offset, `ParentUUID`→children. Use Block Index Table if present.
6. **Import check.** `Flags` bit 0 set? Read Import Provenance.
7. **Payloads.** Regions via PageStateMap. Modules via pad8 offsets.

---

## 12. Worked Example

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
| `0x10` | BlockUUID | (16B) | UUIDv4 |
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

## 13. Conformance

### 13.1 Producer

A conformant producer **MUST:** (1) write a valid header with `Magic`, `Endianness` (default `0x01`), `HeaderSize`, `Version`; (2) use byte order per `Endianness`; (3) generate UUIDv4 in RFC 4122 network byte order; (4) compute BLAKE3 `PrevHash`: Block 0 hashes the header, subsequent blocks hash the preceding block; (5) set reserved fields to zero; (6) pad8 all variable fields; (7) never modify written blocks; (8) set `CapBitmap` accurately; (9) if importing: set `Flags` bit 0 and emit Import Provenance as Block 0; (10) set `PayloadVersion` to 1 for v1.0 layouts; (11) set `CompAlgo` to `00` when `Compressed` is not set; (12) split regions exceeding `2^32 − 81` bytes using Continuation blocks; (13) write 32 zero bytes into `DiskHash` when unavailable; (14) reject `PageSizeLog2` outside [10, 40].

A conformant acquirer **MUST** emit a Process Identity block (`0x0040`) as the first capture-time block.

A conformant producer **SHOULD** emit an End-of-Capture block (type `0x0FFF`) as the final capture-time block.

### 13.2 Consumer

A conformant consumer **MUST:** (1) reject invalid file magic or `Endianness`; (2) use `HeaderSize` to locate Block 0; (3) skip unknown block types via `BlockLength`; (4) detect end-of-blocks when <80 bytes remain or next 4 bytes ≠ `0x4D534C43`; (5) ignore reserved fields; (6) reject block type `0x0000`; (7) skip unknown `PayloadVersion` via `BlockLength`; (8) treat all-zero `DiskHash` as unavailable; (9) ignore `CompAlgo` when `Compressed` is not set; (10) reject `PageSizeLog2` outside [10, 40].

A conformant consumer **SHOULD:** (1) verify the BLAKE3 chain; (2) verify EoC `FileHash` if present; (3) check `CapBitmap` before searching for specific block types; (4) use the Block Index Table for random access when present.

---

## References

1. S. Bradner, "Key words for use in RFCs to Indicate Requirement Levels," RFC 2119, 1997.
2. P. Leach, M. Mealling, R. Salz, "A Universally Unique IDentifier (UUID) URN Namespace," RFC 4122, 2005.
3. J. O'Connor et al., "BLAKE3: One function, fast everywhere," 2020.
4. TIS Committee, "ELF Specification," v1.2, 1995.
