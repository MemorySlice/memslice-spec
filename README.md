# Memory Slice (.msl) Specification

**A self-describing, block-based binary format for process-centric memory forensics.**

Memory Slice captures the complete forensic state of a single operating system process: the virtual address space with per-page acquisition status (Captured / Failed / Unmapped) and transient OS metadata that exists only while the process is alive -- threads, file descriptors, loaded modules, network connections, and more.

## Key Properties

- **Append-only integrity** -- BLAKE3 hash chain from file header through every block
- **Three-state page map** -- distinguishes successfully read pages from failed reads and TOCTOU unmaps
- **Self-describing** -- endianness, version, OS, architecture, PID, and capability bitmap in the header
- **Dual-layer OS abstraction** -- normalized cross-platform fields plus OS-native opaque blobs
- **Enrichable** -- analysis tools append Structural and Semantic blocks without modifying capture data
- **Import-friendly** -- raw dumps (`/proc/pid/mem`, ELF cores, Minidumps, ProcDump) convert to MSL with full provenance tracking

## Specification

| Format | Link |
|--------|------|
| Markdown | [Memory_Slice_Specification.md](Memory_Slice_Specification.md) |
| PDF | [Memory_Slice_Specification.pdf](Memory_Slice_Specification.pdf) |

**Version:** draft-2026-07 (Working Draft)

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
