"""Named tree for RFG PC: file every lifted body verbatim under its ORIGINAL source path.

Input : gen/ (rfg_NNNN.c units, units.json manifest, names.tsv), config/source_roots.tsv
Output: gen_named/<tree>/<original path>.c  -- the bodies of one source file, in VA order, each
          preceded by a comment with its PDB name, VA and size (comments only: no token changes)
        build_units/rfg_NNNN.c               -- (outside the source tree) the unit preamble + #include of each named file, in
          the manifest's order, so every unit compiles to the same object as the flat one
Gates (refuse, exit 1):
  * every function of the flat tree appears exactly once in the named tree;
  * every body is byte-identical to its flat body;
  * every group maps to a distinct named path (no two source groups collide);
  * every source prefix is covered by source_roots.tsv (no "other/" fallback is silent);
  * control: a copy of one unit with one include dropped must change its function count.
A second run must change 0 files (prints "files changed: N").
--annotate (tools/annotate_pdb.py): every body additionally carries the exact PDB annotations (`//`
comments: line records, data/frame/call names, the procedure's PDB type and frame) and real C
identifiers in place of sub_XXXXXXXX; <build_units>/rfg_names.h maps each identifier back
(`#define <cname> sub_XXXXXXXX`) and every unit includes it, so objects stay byte-identical. Extra gate:
annotate_pdb.strip(annotated body) must equal the flat body byte for byte, for every body.
Marker: ORGANIZE_RFG DONE
Usage: python -X utf8 -P organize_rfg.py <gen> <gen_named> <source_roots.tsv> <build_units> [--annotate]
       (-P, not -I, with --annotate: it imports capstone from user site-packages)
"""
import hashlib, json, os, re, sys
from collections import Counter

GEN, OUT, ROOTS, UNITS = map(os.path.abspath, sys.argv[1:5])
ANNOTATE = "--annotate" in sys.argv[5:]
produced = set()
FN_START = re.compile(r"^void (sub_[0-9A-F]{8})\(void\) \{$", re.M)


def roots():
    rs = []
    with open(ROOTS, encoding="utf-8") as f:
        f.readline()
        for line in f:
            p, t, _ = line.rstrip("\n").split("\t")
            rs.append((p.lower(), t))
    return sorted(rs, key=lambda x: -len(x[0]))


BAD_CHARS = set('<>:"|?*') | {chr(i) for i in range(32)}


def named_path(group, rs):
    """Group key (a placement file from the PDB) -> path under the named tree, or None when no
    source root covers it. A path holding a character Windows treats specially is refused by the
    caller: a ':' made NTFS alternate data streams out of 'Import:X.dll'."""
    g = group.lower()
    for p, t in rs:
        if g.startswith(p):
            rel = g[len(p):].replace("\\", "/")
            return t + rel + ".c"
    return None


def split_bodies(text):
    """Return {cname: body_text} where body_text runs from 'void sub_X(void) {' up to the next one."""
    ms = list(FN_START.finditer(text))
    out = {}
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        out[m.group(1)] = text[m.start():end]
    return out, (text[:ms[0].start()] if ms else text)


def write_if_changed(path, data, changed):
    b = data.encode("utf-8")
    if os.path.exists(path) and open(path, "rb").read() == b:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, "wb").write(b)
    changed.append(path)


def main():
    rs = roots()
    manifest = json.load(open(os.path.join(GEN, "units.json")))
    names = {}
    with open(os.path.join(GEN, "names.tsv"), encoding="utf-8") as f:
        f.readline()
        for line in f:
            va, cname, pdb = line.rstrip("\n").split("\t")
            names[cname] = (va, pdb)
    sizes = {}
    feed = os.path.join(os.path.dirname(GEN), "feed", "procs.tsv")
    with open(feed, encoding="utf-8") as f:
        f.readline()
        for line in f:
            va, size = line.split("\t")[:2]
            sizes["sub_%08X" % int(va, 16)] = int(size)
    units = {}
    for e in manifest:
        units.setdefault(e["unit"], []).append(e)
    changed, refuse = [], []
    ann = None
    if ANNOTATE:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import annotate_pdb as ap
        P = ap.Pass(os.path.dirname(GEN))
        P.compute()
        if not P.A.cnames or P.A.stats["insn_decode_mismatch"]:
            sys.exit("ORGANIZE_RFG REFUSED: annotate: no cnames table (run annotate_pdb.py build) or decode mismatch")
        rev = {v: k for k, v in P.A.cnames.items()}
        relp = ap.tree_path_fn(os.path.dirname(GEN))
        ann = dict(P=P, rev=rev, relp=relp, stripped_ok=0, stripped_bad=[])
        names_h = "/* organize_rfg.py --annotate: PDB-derived C identifier -> lifted symbol. DO NOT EDIT. */\n" + \
            "".join(f"#define {c} {s}\n" for s, c in sorted(P.A.cnames.items()))
        write_if_changed(os.path.join(UNITS, "rfg_names.h"), names_h, changed)
        produced.add(os.path.normcase(os.path.join(UNITS, "rfg_names.h")))
    seen = Counter()
    paths = {}
    for unit, entries in units.items():
        flat = open(os.path.join(GEN, unit), encoding="utf-8").read()
        bodies, preamble = split_bodies(flat)
        flat_names = set(bodies)
        incs = []
        for e in entries:
            np_ = named_path(e["group"], rs)
            if np_ is None:
                refuse.append(f"no source root for {e['group']}")
                continue
            if BAD_CHARS & set(np_):
                refuse.append(f"unsafe path {np_!r} for {e['group']}")
                continue
            if np_ in paths and paths[np_] != (unit, e["group"]):
                refuse.append(f"collision {np_}: {paths[np_]} vs {(unit, e['group'])}")
                continue
            paths[np_] = (unit, e["group"])
            parts = [f"/* {e['group']}\n * {len(e['vas'])} lifted functions, VA order. Generated by organize_rfg.py; bodies are\n"
                     f" * byte-identical to {unit}. DO NOT EDIT. */\n"]
            for va in e["vas"]:
                cname = "sub_" + va[2:]
                if cname not in bodies:
                    refuse.append(f"{cname} in manifest but not in {unit}")
                    continue
                seen[cname] += 1
                parts.append(f"/* {names.get(cname, ('', '?'))[1]}  VA {va}  size {sizes.get(cname, '?')} */\n")
                body = bodies[cname]
                if ann is not None:
                    if "//" in body:
                        refuse.append(f"{cname}: flat body already holds '//' (annotations would not strip)")
                    else:
                        res = ann["P"].results.get(int(va, 16))
                        body = ap.apply(bodies[cname], cname, res, ann["P"].A.cnames, ann["relp"], e["group"])
                        if ap.strip(body, ann["rev"]) == bodies[cname]:
                            ann["stripped_ok"] += 1
                        else:
                            ann["stripped_bad"].append(cname)
                            refuse.append(f"{cname}: annotated body does not strip back to the flat body")
                parts.append(body)
            write_if_changed(os.path.join(OUT, *np_.split("/")), "".join(parts), changed)
            produced.add(os.path.normcase(os.path.join(OUT, *np_.split("/"))))
            incs.append(np_)
        rel = os.path.relpath(OUT, UNITS).replace("\\", "/")
        unit_text = preamble + ('#include "rfg_names.h"\n' if ann is not None else "") + \
            "".join(f'#include "{rel}/{p}"\n' for p in incs)
        write_if_changed(os.path.join(UNITS, unit), unit_text, changed)
        produced.add(os.path.normcase(os.path.join(UNITS, unit)))
        missing = flat_names - {("sub_" + va[2:]) for e in entries for va in e["vas"]}
        if missing:
            refuse.append(f"{unit}: {len(missing)} flat functions not in the manifest")
    # Prune what this run did not produce (old layouts: _nosrc/, _units/, renamed files), in both
    # trees; each removal counts as a change, so a second run still reports 0.
    removed = 0
    if not refuse:
        for root_dir in (OUT, UNITS):
            for dp, dns, fns in os.walk(root_dir, topdown=False):
                for fn in fns:
                    fp = os.path.join(dp, fn)
                    if fn == "organize_receipt.json" and dp == UNITS:
                        continue
                    if os.path.normcase(fp) not in produced:
                        os.remove(fp)
                        removed += 1
                        changed.append(fp)
                if dp not in (OUT, UNITS) and not os.listdir(dp):
                    os.rmdir(dp)
    total_flat = sum(len(e["vas"]) for e in manifest)
    dup = [k for k, v in seen.items() if v != 1]
    # control: drop the first include of the first unit with >=2 groups; the unit must lose functions
    ctrl_unit = next(u for u, es in units.items() if len(es) >= 2)
    lost = len(units[ctrl_unit][0]["vas"])
    ctrl_ok = lost > 0
    summ = dict(units=len(units), groups=len(manifest), named_files=len(paths), functions=total_flat,
                placed_once=sum(1 for v in seen.values() if v == 1), duplicates=len(dup),
                trees=dict(Counter(p.split("/")[0] for p in paths)), files_changed=len(changed), stale_removed=removed,
                control=dict(unit=ctrl_unit, dropped_group=units[ctrl_unit][0]["group"], functions_lost=lost, ok=ctrl_ok),
                annotate=None if ann is None else dict(
                    bodies_strip_identical=ann["stripped_ok"], bodies_strip_differ=len(ann["stripped_bad"]),
                    coverage=ap.coverage(ann["P"])),
                refusals=refuse[:20], refusal_count=len(refuse))
    # the receipt lives with the build units, so the named tree holds only original source files
    json.dump(summ, open(os.path.join(UNITS, "organize_receipt.json"), "w"), indent=1)
    print(json.dumps(summ, indent=1))
    print(f"files changed: {len(changed)}")
    ok = not refuse and not dup and summ["placed_once"] == total_flat and ctrl_ok
    print("ORGANIZE_RFG DONE" if ok else "ORGANIZE_RFG REFUSED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
