#!/usr/bin/env python3
"""Render PROVENANCE.md's per-family anchor table from the controls' own tags.

The table lists, for each EF family, the union of what its controls carry in
`tag nist:`, `tag srg:`, `tag cci:` and `tag fsbp:`. It is written between the
two markers below and nowhere else, so the hand-written prose around it stays
as authored.

Usage:
    python3 tools/render_provenance.py            # rewrite the generated block
    python3 tools/render_provenance.py --check    # exit 1 if the block is stale

stdlib only.
"""
import argparse
import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = ROOT / "PROVENANCE.md"
BEGIN = "<!-- BEGIN GENERATED: family anchors (tools/render_provenance.py) -->"
END = "<!-- END GENERATED: family anchors -->"
ID_RE = re.compile(r"""^\s*control\s+['"](EF-(\d+)\.\d+)['"]""", re.M)
STATUS_RE = re.compile(r"""^\s*tag\s+implementation_status:\s*['"]([^'"]+)['"]""", re.M)
PLACEHOLDERS = {"", "n/a", "none", "-", "—"}


def tag_values(text, name):
    """Literal string values of `tag <name>:`, whether a list or a scalar."""
    m = re.search(rf"""^\s*tag\s+{name}:\s*(\[[^\]]*\]|'[^']*'|"[^"]*")""", text, re.M)
    if not m:
        return []
    return [v for v in re.findall(r"""['"]([^'"]+)['"]""", m.group(1))
            if v.strip().lower() not in PLACEHOLDERS]


def natural(value):
    """Sort 'AC-6 (8)' after 'AC-6 (2)' and 'SC-28' after 'SC-8'."""
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", value)]


def collect(controls_dir):
    families = collections.defaultdict(lambda: {
        "ids": [], "status": collections.Counter(),
        "nist": set(), "srg": set(), "cci": set(), "fsbp": set()})
    for path in sorted(controls_dir.glob("*.rb")):
        text = path.read_text(encoding="utf-8")
        m = ID_RE.search(text)
        if not m:
            continue
        fam = families[int(m.group(2))]
        fam["ids"].append(m.group(1))
        status = STATUS_RE.search(text)
        fam["status"][status.group(1) if status else "unstated"] += 1
        for key in ("nist", "srg", "cci", "fsbp"):
            fam[key].update(tag_values(text, key))
    return families


def render(families):
    rows = [
        "| Family | Controls | NIST 800-53r5 (`tag nist`) | DISA SRG-CTR (`tag srg`) | CCI (`tag cci`) | FSBP (`tag fsbp`) |",
        "|---|---|---|---|---|---|",
    ]
    for num in sorted(families):
        fam = families[num]
        ids = sorted(fam["ids"], key=natural)
        status = ", ".join(f"{n} {s}" for s, n in sorted(fam["status"].items()))
        cells = [", ".join(sorted(fam[k], key=natural)) or "—" for k in ("nist", "srg", "cci", "fsbp")]
        rows.append(f"| **EF-{num}** | {len(ids)} ({status}): {ids[0]}…{ids[-1]} | " + " | ".join(cells) + " |")
    total = sum(len(f["ids"]) for f in families.values())
    return "\n".join(rows) + f"\n\n{total} controls across {len(families)} families.\n"


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="exit 1 if the generated block is stale")
    args = ap.parse_args(argv)

    doc = DOC.read_text(encoding="utf-8")
    if BEGIN not in doc or END not in doc:
        print(f"{DOC.name}: generated-block markers not found", file=sys.stderr)
        return 2
    head, rest = doc.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    updated = f"{head}{BEGIN}\n{render(collect(ROOT / 'controls'))}{END}{tail}"

    if args.check:
        if updated != doc:
            print(f"{DOC.name} is stale. Run: python3 tools/render_provenance.py", file=sys.stderr)
            return 1
        print(f"{DOC.name} family anchors are in sync with controls/.")
        return 0
    if updated == doc:
        print(f"{DOC.name} already in sync; nothing written.")
        return 0
    DOC.write_text(updated, encoding="utf-8")
    print(f"Rewrote the family-anchor block in {DOC.name}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
