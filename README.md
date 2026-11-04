# Memory Slice (.msl) Specification

**A self-describing, block-based binary format for process-centric memory forensics.**

Memory Slice captures the complete forensic state of a single operating system process: the virtual address space with per-page acquisition status (Captured / Failed / Unmapped / NotResident) and transient OS metadata that exists only while the process is alive -- threads, file descriptors, loaded modules, network connections, and more.

## Key Properties

- **Append-only integrity** -- hash chain (BLAKE3 by default, selectable `HashAlgo`) from file header through every block, including appended extension segments
- **Four-state page map** -- distinguishes successfully read pages from failed reads, TOCTOU unmaps, and never-touched (zero) pages
- **Self-describing** -- endianness, version, OS, architecture, PID, and capability bitmap in the header
- **Dual-layer OS abstraction** -- normalized cross-platform fields plus OS-native opaque blobs
- **Enrichable** -- analysis tools append Structural and Semantic blocks without modifying capture data
- **Extension segments** -- post-acquisition blocks are grouped into self-verifying segments terminated by an End-of-Extension block (`0x0FFE`); the capture segment and header stay byte-for-byte untouched
- **Thread Context** -- per-thread register files (`0x0011`) for emulation and stack attribution
- **Import-friendly** -- raw dumps (`/proc/pid/mem`, ELF cores, Minidumps, ProcDump) convert to MSL with full provenance tracking

## Specification

| Format | Link |
|--------|------|
| Markdown | [Memory_Slice_Specification.md](Memory_Slice_Specification.md) |
| PDF | [Memory_Slice_Specification.pdf](Memory_Slice_Specification.pdf) |

**Version:** 1.1.2 (Working Draft)

## Implementations

Tools that produce (write) or consume (read) `.msl` files:

| Project | Language | Role | Description |
|---------|----------|------|-------------|
| [memslicer](https://github.com/MemorySlice/memslicer) | Python | Producer | Process memory acquisition via Frida, GDB and LLDB; `memslicer-enrich` appends extension segments |
| [memslicer-rs](https://github.com/MemorySlice/memslicer-rs) | Rust | Producer | Frida-based cross-platform process memory acquisition |
| [libmsl](https://github.com/MemorySlice/libmsl) | Rust | Library | Streaming and zero-copy reader, streaming writer |
| [MemDiver](https://github.com/MemorySlice/MemDiver) | Python | Consumer | Interactive identification and analysis of data structures in memory dumps |
| [radare2 `msl` plugins](https://github.com/radareorg/radare2-extras/tree/master/msl) | C | Consumer, Producer | `io.msl`/`bin.msl` open a slice as a CORE object; `debug.msl` emulates (ESIL) from the captured Thread Context, with thread selection and reverse stepping; `core.msl` writes a slice from a live debug session (`dgm`) |
| [BinTopsy](https://github.com/reverseame/BinTopsy) | Python | Consumer, Producer | Static triage of the captured process image (IAT rebuilt from the slice's module list and PE exports, ATT&CK mapping, IoCs); appends its results as Analysis Findings (`0x1B70`, schema `bintopsy-findings/1`) in an extension segment |

To list another implementation, open a pull request.

## Building the PDF

The LaTeX source is self-contained, but it needs a specific TeX Live package set
(TikZ, `tcolorbox`, `bytefield`, ...). The included `Dockerfile` pins that set so the
build is identical on macOS, Linux and Windows -- no local TeX installation required.

```bash
# macOS / Linux (bash, zsh)
docker build -t msl-spec .
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/doc" msl-spec
```

```powershell
# Windows (PowerShell)
docker build -t msl-spec .
docker run --rm -v "${PWD}:/doc" msl-spec
```

The result is written to `build/Memory_Slice_Specification.pdf`; the committed PDF above
is left untouched. Pass a filename to compile a different document, e.g.
`docker run --rm -v "$PWD:/doc" msl-spec Other.tex`.

## License

See the specification document for terms.
