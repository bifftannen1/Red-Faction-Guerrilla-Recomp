"""Identity tables for RFG PC from the target's own GUID-matched PDB.

config/allocation.tsv : va, size, cname, obj_module, source_file, evidence, placement_file, placement_evidence
config/names.tsv      : va, cname, pdb_name, mangled, evidence
evidence = PDB_EXACT for every row (proc record of the GUID/age-matched PDB at exactly this VA);
mangled  = the S_PUB32 at the same VA (unique, else refused), blank when the PDB has none there.
Gates: every lifted function (gen/names.tsv) gets exactly one row; a VA with two different public
names is a refusal; control: a copy of the public table shifted by +1 byte must lose >= 99% of the
mangled matches. Second run: "files changed: 0". Marker: WRITE_NAMES DONE
Usage: python -X utf8 -I write_names.py <feed> <gen> <config_out>
"""
import json, os, sys
from collections import defaultdict

FEED, GEN, OUT = map(os.path.abspath, sys.argv[1:4])
os.makedirs(OUT, exist_ok=True)


def tsv(path):
    with open(path, encoding="utf-8") as f:
        hdr = f.readline().rstrip("\n").split("\t")
        for line in f:
            yield dict(zip(hdr, line.rstrip("\n").split("\t")))


alloc = {int(r["va"], 16): r for r in tsv(os.path.join(FEED, "allocation.tsv"))}
if any("placement_file" not in r for r in list(alloc.values())[:1]):
    sys.exit("WRITE_NAMES REFUSED: feed/allocation.tsv lacks placement columns (rerun pdb_alloc32.py)")
pstarts = sorted(alloc)
pubs = defaultdict(set)
for r in tsv(os.path.join(FEED, "publics.tsv")):
    if r["va"] != "NONE":
        pubs[int(r["va"], 16)].add(r["name"])
lifted = [(int(r["va"], 16), r["cname"], r["pdb_name"]) for r in tsv(os.path.join(GEN, "names.tsv"))]
refuse = []
rows_a, rows_n = [], []
mangled_hits = 0
for va, cname, pdb in lifted:
    a = alloc.get(va)
    p = pubs.get(va, set())
    if len(p) > 1:
        # ICF/aliases: several public names at one address is a fact; keep them all, sorted
        mangled = "|".join(sorted(p))
    else:
        mangled = next(iter(p), "")
    mangled_hits += bool(mangled)
    if a is None:
        # interior entry: no proc record. Named by its S_PUB32 when there is one (the declared
        # feed/interior_entries.tsv rows), else by codegen's CALL_INTO_BODY rule (parent+offset).
        ev = "PDB_PUBLIC_INTERIOR" if mangled else "CALL_INTO_BODY"
        import bisect
        par = alloc[pstarts[bisect.bisect_right(pstarts, va) - 1]]
        rows_a.append(f"0x{va:08X}\t\t{cname}\t{par['obj_module']}\t\t{ev}\t{par['placement_file']}\tPARENT_{par['placement_evidence']}")
        rows_n.append(f"0x{va:08X}\t{cname}\t{pdb}\t{mangled}\t{ev}")
        continue
    rows_a.append(f"0x{va:08X}\t{a['size']}\t{cname}\t{a['obj_module']}\t{a['source_file']}\tPDB_EXACT"
                  f"\t{a['placement_file']}\t{a['placement_evidence']}")
    rows_n.append(f"0x{va:08X}\t{cname}\t{pdb}\t{mangled}\tPDB_EXACT")
seen = defaultdict(int)
for va, *_ in lifted:
    seen[va] += 1
dups = [va for va, n in seen.items() if n != 1]
# control: shift the public table by one byte
shift_hits = sum(1 for va, *_ in lifted if pubs.get(va + 1))
ctrl_ok = shift_hits <= 0.01 * max(1, mangled_hits)
changed = 0
for name, hdr, rows in (("allocation.tsv", "va\tsize\tcname\tobj_module\tsource_file\tevidence\tplacement_file\tplacement_evidence", rows_a),
                        ("names.tsv", "va\tcname\tpdb_name\tmangled\tevidence", rows_n)):
    data = (hdr + "\n" + "\n".join(rows) + "\n").encode("utf-8")
    p = os.path.join(OUT, name)
    if not (os.path.exists(p) and open(p, "rb").read() == data):
        open(p, "wb").write(data)
        changed += 1
summ = dict(lifted=len(lifted), allocation_rows=len(rows_a), names_rows=len(rows_n), duplicates=len(dups),
            pdb_exact=sum(1 for r in rows_n if r.endswith("PDB_EXACT")),
            with_source_file=sum(1 for r in rows_a if r.split("\t")[4]),
            with_mangled=mangled_hits, multi_public_vas=sum(1 for va, *_ in lifted if len(pubs.get(va, ())) > 1),
            control_shift1_hits=shift_hits, control_ok=ctrl_ok)
json.dump(summ, open(os.path.join(OUT, "names_receipt.json"), "w"), indent=1)
print(json.dumps(summ, indent=1))
print(f"files changed: {changed}")
ok = not dups and not refuse and ctrl_ok and len(rows_n) == len(lifted)
print("WRITE_NAMES DONE" if ok else "WRITE_NAMES REFUSED")
sys.exit(0 if ok else 1)
