#!/usr/bin/env python3
"""Reflow spec/scripts/*.txt for the paper's listing appendix.

The generator wraps scripts at 80 columns. For the paper each script is
joined into whitespace-separated paragraphs of at most 1200 characters so that the `listings`
package wraps it at the column width, keeping tokens intact. Headings
(lines starting with '#') are preserved as their own lines.
"""
import glob
import os

SRC = os.path.join(os.path.dirname(__file__), "..", "spec", "scripts")
DST = os.path.join(os.path.dirname(__file__), "listings")
os.makedirs(DST, exist_ok=True)
for path in sorted(glob.glob(os.path.join(SRC, "*.txt"))):
    out, buf = [], []
    WIDTH = 1200  # chars per emitted line; TeX cannot measure a line longer than ~16000pt
    def flush():
        if buf:
            line = []
            n = 0
            for tok in buf:
                if n and n + 1 + len(tok) > WIDTH:
                    out.append(" ".join(line)); line, n = [], 0
                line.append(tok); n += len(tok) + 1
            if line:
                out.append(" ".join(line))
            buf.clear()
    for line in open(path):
        line = line.rstrip("\n")
        if line.startswith("#"):
            flush()
            out.append(line)
        elif not line.strip():
            flush()
            out.append("")
        else:
            buf.extend(line.split())
    flush()
    with open(os.path.join(DST, os.path.basename(path)), "w") as f:
        f.write("\n".join(out) + "\n")
print("reflowed", len(glob.glob(os.path.join(DST, "*.txt"))), "files")
