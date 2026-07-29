# Reproducible pdfLaTeX build for Memory_Slice_Specification.tex
#
# Intentionally NOT platform-pinned, so it builds and runs natively on
# amd64, arm64 (Apple Silicon) and armv7 instead of under emulation.
#
#   docker build -t msl-spec .
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/doc" msl-spec
#
FROM debian:bookworm-slim

# Debian bookworm freezes TeX Live, so this image stays reproducible over time
# and needs no CTAN access at build time (unlike tlmgr / TinyTeX, which break
# with "local TeX Live is older than remote" after an upstream release).
#
# The .tex needs 22 packages; these five texlive-* packages cover all of them:
#   texlive-latex-base        LaTeX core, inputenc, graphicx, longtable, array,
#                             amsmath, hyperref, tabularx
#   texlive-latex-recommended geometry, xcolor, fancyhdr, booktabs, listings,
#                             etoolbox, subcaption (caption bundle)
#   texlive-latex-extra       tcolorbox (+breakable/skins), titlesec, enumitem,
#                             multirow, placeins, float
#   texlive-pictures          pgf/tikz and the requested tikzlibraries
#   texlive-science           bytefield (Debian ships it here, not in -extra)
#   texlive-fonts-recommended standard fonts backing Computer Modern output
#   latexmk                   drives the 2-3 pdflatex passes + rerun detection
#
# --no-install-recommends is what keeps this small: it drops the *-doc
# companion packages, which are the bulk of a naive texlive-latex-extra install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        texlive-latex-base \
        texlive-latex-recommended \
        texlive-latex-extra \
        texlive-pictures \
        texlive-science \
        texlive-fonts-recommended \
        latexmk \
    && rm -rf /var/lib/apt/lists/*

# Point the TeX caches at a world-writable location so the container can run as
# an arbitrary UID (docker run --user "$(id -u):$(id -g)"). Without this, a
# non-root UID cannot write its font/format cache and pdflatex fails; with it,
# files written into the bind-mounted repo are not root-owned on Linux hosts.
ENV HOME=/tmp \
    TEXMFVAR=/tmp/texmf-var \
    TEXMFCONFIG=/tmp/texmf-config

WORKDIR /doc

# The launcher is generated inside the image rather than checked into git, so it
# always has LF endings even when the repo is cloned on Windows with
# core.autocrlf=true. printf is used instead of a Dockerfile heredoc because
# heredocs require BuildKit frontend 1.4+, which older Docker daemons lack.
RUN printf '%s\n' \
        '#!/bin/sh' \
        'set -e' \
        'mkdir -p build' \
        'exec latexmk -pdf -interaction=nonstopmode -halt-on-error -file-line-error -outdir=build "$@"' \
        > /usr/local/bin/build-pdf \
    && chmod +x /usr/local/bin/build-pdf

# Everything (PDF + .aux/.log/.toc) lands in ./build/ so the committed
# Memory_Slice_Specification.pdf is never overwritten.
ENTRYPOINT ["/usr/local/bin/build-pdf"]
CMD ["Memory_Slice_Specification.tex"]
