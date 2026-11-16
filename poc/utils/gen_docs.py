#!/usr/bin/env python3
"""Regenerate the doc/*.md index row blocks from the `# INDEX:` taglines in poc/**."""
# Usage: from the repo root, run `python3 -I poc/utils/gen_docs.py`
# Each indexed module carries one header line  `# INDEX: <what> | <sapi> | <gate>`
# (gate optional). This drives three indexes:
#   doc/PRIMITIVES.md  rows grouped under a `## <folder>` heading per poc/primitives/ subfolder
#   doc/CHAINS.md      flat sorted list of poc/chains/*.py, each with access/sink/offset chips
#   doc/BUGS.md        flat sorted list of poc/bugs/*.py
# Each row is  - `<file>` — <what> · <sapi> · <gate>   (the ` · <gate>` dropped when absent).
# Hand-written top matter (and, for PRIMITIVES, the headings + their comments) is preserved
# as-is; only the `- ` row lines are (re)generated, so a second run is a no-op.
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Primitives sections mirror the exploitation flow, geometry last.
PRIM_SECTIONS = ["read_leak", "write", "groom", "oracles",
                 "dispatch", "encode", "shm", "tooling", "geometry"]
# Comments written for primitives folders that have no section in the doc yet.
PRIM_NEW_SECTION_COMMENT = {
    "geometry": "Heap-layout geometry — decode-allocation strides and offsets for placing forged structures.",
}

# Each doc: source folder under poc/, output path, and layout.
# `sections` lists the subfolder sections in order (PRIMITIVES); None = flat list.
DOCS = [
    {"src": ROOT / "poc" / "primitives", "doc": ROOT / "doc" / "PRIMITIVES.md",
     "sections": PRIM_SECTIONS, "new_comments": PRIM_NEW_SECTION_COMMENT},
    {"src": ROOT / "poc" / "chains", "doc": ROOT / "doc" / "CHAINS.md",
     "sections": None, "new_comments": {}, "caps": True},
    {"src": ROOT / "poc" / "bugs", "doc": ROOT / "doc" / "BUGS.md",
     "sections": None, "new_comments": {}},
]


def read_index(path):
    """Return the stripped text after `# INDEX:`, or None if the module has no tagline."""
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("# INDEX:"):
                return line[len("# INDEX:"):].strip()
    return None


def format_row(name, idx, caps=False):
    """Build a doc row from a module filename and its `# INDEX:` payload.
    Plain layout: `what | sapi | gate`. Capability layout (chains, caps=True):
    `what | sapi | access | sink | offset | gate` renders access/sink/offset as
    their own chips; the gate stays optional and last."""
    parts = [p.strip() for p in idx.split("|")]
    if caps and len(parts) >= 5:
        fields = parts[:5]                        # what, sapi, access, sink, offset
        gate = " | ".join(parts[5:]).strip()      # anything after offset is the gate
        if gate:
            fields = fields + [gate]
        return "- `" + name + "` — " + " · ".join(fields)
    what = parts[0]
    fields = [what]
    if len(parts) > 1 and parts[1]:
        fields.append(parts[1])                       # sapi
    if len(parts) > 2 and " | ".join(parts[2:]).strip():
        fields.append(" | ".join(parts[2:]).strip())  # gate
    return "- `" + name + "` — " + " · ".join(fields)


def scan_dir(d, caps=False):
    """Return the rows for modules directly in dir `d`, sorted by filename.
    Skips verify_/_/__init__ and untagged files."""
    items = []
    if not d.is_dir():
        return items
    for name in os.listdir(d):
        if not name.endswith(".py"):
            continue
        if name.startswith("_") or name.startswith("verify_") or name == "__init__.py":
            continue
        idx = read_index(d / name)
        if idx is None:
            continue
        items.append((name, format_row(name, idx, caps)))
    items.sort(key=lambda t: t[0])
    return [row for _, row in items]


# ---- sectioned docs (PRIMITIVES): rows grouped under `## <folder>` headings ----
def parse_sectioned(text):
    """Split into top matter (pre first heading) and each folder's comment lines."""
    lines = text.split("\n")
    first = next((i for i, l in enumerate(lines) if l.startswith("## ")), len(lines))
    pre, comments, i = lines[:first], {}, first
    while i < len(lines):
        folder = lines[i][3:].strip()
        i += 1
        cmts = []
        # Comment block: contiguous non-blank, non-row lines directly under the heading.
        while (i < len(lines) and not lines[i].startswith("## ")
               and lines[i].strip() != "" and not lines[i].lstrip().startswith("- ")):
            cmts.append(lines[i])
            i += 1
        comments[folder] = cmts
        while i < len(lines) and not lines[i].startswith("## "):  # discard old rows/blanks
            i += 1
    return pre, comments


def build_sectioned(pre, comments, src, sections, new_comments):
    """Reassemble: preserved top matter and headers, freshly generated rows."""
    pre = list(pre)
    while pre and pre[-1].strip() == "":  # drop trailing blanks; separators re-added below
        pre.pop()
    out = list(pre)
    for folder in sections:
        cmts = comments.get(folder)
        if cmts is None:
            cmts = [new_comments[folder]] if folder in new_comments else []
        out.append("")
        out.append("## " + folder)
        out.extend(cmts)
        out.append("")
        out.extend(scan_dir(src / folder))
    return "\n".join(out) + "\n"


# ---- flat docs (CHAINS, BUGS): one sorted list below the top matter ----
def parse_flat(text):
    """Top matter = everything before the first `- ` row line, trailing blanks dropped."""
    lines = text.split("\n")
    first = next((i for i, l in enumerate(lines) if l.lstrip().startswith("- ")), len(lines))
    pre = lines[:first]
    while pre and pre[-1].strip() == "":
        pre.pop()
    return pre


def build_flat(pre, rows):
    return "\n".join(list(pre) + [""] + rows) + "\n"


def regenerate(spec):
    """Rewrite one doc in place if its rows changed. Returns (counts, changed)."""
    old = spec["doc"].read_text(encoding="utf-8")
    if spec["sections"] is None:
        rows = scan_dir(spec["src"], spec.get("caps", False))
        new = build_flat(parse_flat(old), rows)
        counts = [(spec["src"].name, len(rows))]
    else:
        pre, comments = parse_sectioned(old)
        new = build_sectioned(pre, comments, spec["src"], spec["sections"], spec["new_comments"])
        counts = [(s, len(scan_dir(spec["src"] / s))) for s in spec["sections"]]
    changed = new != old
    if changed:
        spec["doc"].write_text(new, encoding="utf-8")
    return counts, changed


def main():
    for spec in DOCS:
        counts, changed = regenerate(spec)
        print(spec["doc"].relative_to(ROOT))
        total = 0
        for label, n in counts:
            total += n
            print(f"  {label:<10} {n}")
        print(f"  {'TOTAL':<10} {total}  ({'updated' if changed else 'unchanged'})")


if __name__ == "__main__":
    main()
