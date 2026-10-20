"""Independent re-check of the PDB annotations in an annotated named tree (organize_rfg.py --annotate).

Second reader: MSF via probes/pdb_procs32.py (a different implementation from tools/pdb_tpi.py,
which annotate_pdb.py uses) and its own walk of module symbols, C13 lines, publics and the few TPI
records it needs. Nothing from annotate_pdb.py is imported except the text strip() used for gate 1.

Gates (exit 1 unless all hold):
  1. strip: every body of the tree, stripped of `//` comments and with cnames mapped back through
     <units>/rfg_names.h, equals the flat body in gen/ byte for byte; every flat body appears once.
     Control: one body with one code character changed must be caught.
  2. records: every annotation is backed by a record at exactly its address (second reader):
       `// line N` / `// <path>:N`   a C13 line record at the anchor instruction's VA with that line
       `// label X`                  S_LABEL32 X at the anchor VA
       `0xADDR=name(+off)`           data symbol `name` at ADDR-off, a public at ADDR, a procedure (cname)
                                     at ADDR, or a label at ADDR
       `[expr]=name`                 a S_BPREL32/S_REGREL32 `name` in the enclosing procedure
       `import X`                    public __imp_X at the call's IAT address
       `icall ...` / `vcall C::m`    S_CALLSITEINFO at the call's VA (vcall: its LF_MFUNCTION class is C)
       header `PDB ... name(`        the procedure record at the body's VA has that name
     Every mismatch is listed (first 30) and counted per kind.
  3. shift control: annotations computed from facts shifted by +SHIFT bytes (annotate_pdb.Pass(shift))
     for a sample of bodies must FAIL gate 2 for lines, data and calls (mismatches, or the kind vanishing).
Usage: python -X utf8 -P tools/verify_pdb_annot.py <rfg_pc_recomp> <named_tree> <units_dir> [--shift 16]
Marker: VERIFY_PDB_ANNOT PASS
"""
import collections, json, os, re, struct, sys, time

ROOT, TREE, UNITS = map(os.path.abspath, sys.argv[1:4])
SHIFT = int(sys.argv[sys.argv.index("--shift") + 1]) if "--shift" in sys.argv else 16
sys.path.insert(0, os.path.join(ROOT, "probes"))
from pdb_procs32 import MSF, dbi, read_pe, section_rvas, walk_syms, cstr  # noqa: E402


# ------------------------------------------------------------------------------------------ second reader
class Reader2:
    def __init__(self):
        base, entry, pe_secs = read_pe(os.path.join(ROOT, "input", "rfg.exe"))
        msf = MSF(os.path.join(ROOT, "input", "rfg.pdb"))
        info = dbi(msf)
        secs = section_rvas(msf, info, pe_secs)
        self.base = base

        def va(seg, off):
            return base + secs[seg - 1][1] + off if 1 <= seg <= len(secs) else None
        # /names
        s1 = msf.stream(1)
        blen = struct.unpack_from("<I", s1, 28)[0]
        nbuf = s1[32:32 + blen]
        o = 32 + blen
        _, cap = struct.unpack_from("<II", s1, o)
        npres = struct.unpack_from("<I", s1, o + 8)[0]
        pres = struct.unpack_from("<%dI" % npres, s1, o + 12)
        o += 12 + 4 * npres
        o += 4 + 4 * struct.unpack_from("<I", s1, o)[0]
        names_stream = None
        for i in range(cap):
            if pres[i // 32] >> (i % 32) & 1:
                k, v = struct.unpack_from("<II", s1, o)
                o += 8
                if nbuf[k:nbuf.index(b"\0", k)] == b"/names":
                    names_stream = v
        strtab = msf.stream(names_stream)
        self.procs, self.frame, self.labels, self.callsites = {}, collections.defaultdict(set), {}, {}
        self.data = collections.defaultdict(set)
        self.lines = collections.defaultdict(set)
        s3 = msf.stream(3)
        modi = struct.unpack_from("<i", s3, 24)[0]
        o = 64
        mods = []
        while o < 64 + modi:
            sn, symb, c11, c13 = struct.unpack_from("<HIII", s3, o + 34)
            _, p = cstr(s3, o + 64)
            _, p = cstr(s3, p)
            mods.append((sn, symb, c11, c13))
            o = (p + 3) & ~3
        for sn, symb, c11, c13 in mods:
            if sn == 0xFFFF:
                continue
            st = msf.stream(sn)
            cur = [None, -1]

            def on(kind, b, o, end, cur=cur):
                if cur[0] is not None and o - 4 >= cur[1]:
                    cur[0] = None
                if kind in (0x110F, 0x1110, 0x1146, 0x1147):
                    pend = struct.unpack_from("<I", b, o + 4)[0]
                    off, seg = struct.unpack_from("<IH", b, o + 28)
                    a = va(seg, off)
                    self.procs.setdefault(a, cstr(b, o + 35)[0])
                    cur[0], cur[1] = a, pend
                elif kind == 0x110B and cur[0] is not None:
                    self.frame[cur[0]].add(cstr(b, o + 8)[0])
                elif kind == 0x1111 and cur[0] is not None:
                    self.frame[cur[0]].add(cstr(b, o + 10)[0])
                elif kind == 0x1106 and cur[0] is not None:
                    self.frame[cur[0]].add(cstr(b, o + 6)[0])
                elif kind in (0x110C, 0x110D):
                    typ, off, seg = struct.unpack_from("<IIH", b, o)
                    a = va(seg, off)
                    nm = cstr(b, o + 10)[0]
                    if cur[0] is not None:
                        self.data[a].add(self.procs[cur[0]] + "::" + nm)
                    else:
                        self.data[a].add(nm)
                elif kind == 0x1105:
                    off, seg = struct.unpack_from("<IH", b, o)
                    self.labels[va(seg, off)] = cstr(b, o + 7)[0]
                elif kind == 0x1139:
                    off, seg, _, typ = struct.unpack_from("<IHHI", b, o)
                    self.callsites[va(seg, off)] = typ
            walk_syms(st[:symb], 4, on)
            c = st[symb + c11:symb + c11 + c13]
            q, chk, blocks = 0, {}, []
            while q + 8 <= len(c):
                kind, ln = struct.unpack_from("<II", c, q)
                body = c[q + 8:q + 8 + ln]
                if kind == 0xF4:
                    r = 0
                    while r + 6 <= len(body):
                        noff, clen = struct.unpack_from("<IB", body, r)
                        chk[r] = strtab[12 + noff:strtab.index(b"\0", 12 + noff)].decode("utf-8", "replace")
                        r = (r + 6 + clen + 3) & ~3
                elif kind == 0xF2:
                    blocks.append(body)
                q += 8 + ((ln + 3) & ~3)
            for body in blocks:
                off, seg, flags, csz = struct.unpack_from("<IHHI", body, 0)
                b0 = va(seg, off)
                r = 12
                while r + 12 <= len(body) and b0 is not None:
                    fid, n, blen = struct.unpack_from("<III", body, r)
                    for i in range(n):
                        lo, fl = struct.unpack_from("<II", body, r + 12 + 8 * i)
                        self.lines[b0 + lo].add((chk.get(fid, "?").lower(), fl & 0xFFFFFF))
                    r += blen
        self.publics = collections.defaultdict(set)

        def on_g(kind, b, o, end):
            if kind == 0x110E:
                flags, off, seg = struct.unpack_from("<IIH", b, o)
                self.publics[va(seg, off)].add(cstr(b, o + 10)[0])
            elif kind in (0x110C, 0x110D):
                typ, off, seg = struct.unpack_from("<IIH", b, o)
                self.data[va(seg, off)].add(cstr(b, o + 10)[0])
        walk_syms(msf.stream(info["symrec"]), 0, on_g)
        # TPI index -> record (only LF_MFUNCTION class and UDT names are read)
        t = msf.stream(2)
        hsz, tb = struct.unpack_from("<II", t, 4)
        nbytes = struct.unpack_from("<I", t, 16)[0]
        self.trec = {}
        o, ti = hsz, tb
        while o < hsz + nbytes:
            ln = struct.unpack_from("<H", t, o)[0]
            self.trec[ti] = t[o + 2:o + 2 + ln]
            o += 2 + ln
            ti += 1

    def class_name_of_mfunc(self, ti):
        r = self.trec.get(ti)
        if r is None:
            return None
        leaf = struct.unpack_from("<H", r, 0)[0]
        if leaf == 0x1002:   # pointer to member function type
            return self.class_name_of_mfunc(struct.unpack_from("<I", r, 2)[0])
        if leaf != 0x1009:
            return None
        cls = struct.unpack_from("<I", r, 6)[0]
        c = self.trec.get(cls)
        if c is None or struct.unpack_from("<H", c, 0)[0] not in (0x1504, 0x1505, 0x1519, 0x1506):
            return None
        leaf = struct.unpack_from("<H", c, 0)[0]
        p = 2 + (8 if leaf == 0x1506 else 16)
        v = struct.unpack_from("<H", c, p)[0]
        p += 2 + ({0x8000: 1, 0x8001: 2, 0x8002: 2, 0x8003: 4, 0x8004: 4, 0x8009: 8, 0x800A: 8}.get(v, 0)
                  if v >= 0x8000 else 0)
        return c[p:c.index(b"\0", p)].decode("utf-8", "replace")


# ------------------------------------------------------------------------------------------ tree parsing
HDR = re.compile(r"^/\* (.*?)  VA 0x([0-9A-F]{8})  size (\S+) \*/\n(void ([A-Za-z_]\w*)\(void\) \{)$", re.M)
INSN = re.compile(r"/\* 0x([0-9A-F]{8}): (.*?) \*/")
LABEL = re.compile(r"^L_([0-9A-F]{8}):")


def tree_bodies(tree):
    for d, _, fs in os.walk(tree):
        for f in sorted(fs):
            if not f.endswith(".c"):
                continue
            p = os.path.join(d, f)
            t = open(p, encoding="utf-8").read()
            ms = list(HDR.finditer(t))
            for i, m in enumerate(ms):
                end = ms[i + 1].start() if i + 1 < len(ms) else len(t)
                yield p, int(m.group(2), 16), t[m.start(4):end]


def items_of(body):
    """-> (header lines, [(va, kind, payload, asm)]) for every annotation of one annotated body."""
    lines = body.split("\n")
    hdr, out = [], []
    commented = set(int(a, 16) for a, _ in INSN.findall(body))
    pre = []
    k = 1
    while k < len(lines) and lines[k].startswith("    // "):
        hdr.append(lines[k][7:])
        k += 1
    after_label = None        # `//` lines right after a label-only anchor belong to that anchor
    for ln in lines[k:]:
        s = ln.strip()
        if s.startswith("//"):
            if after_label is not None:
                out.append((after_label[0], "pre", s[3:], after_label[1]))
            else:
                pre.append(s[3:])
            continue
        after_label = None
        code, _, tail = ln.partition(" //")
        m = INSN.search(code)
        lm = LABEL.match(code)
        if m:
            a, asm = int(m.group(1), 16), m.group(2).strip()
        elif lm and int(lm.group(1), 16) not in commented:
            a, asm = int(lm.group(1), 16), None
            after_label = (a, asm)
        else:
            continue
        for p in pre:
            out.append((a, "pre", p, asm))
        pre = []
        if tail:
            for it in tail.strip().split("; "):
                out.append((a, "note", it, asm))
    # pre lines after a label-only anchor belong to it
    return hdr, out, pre


def check_body(R, va, body, cn2va, own_files, bad, cnt):
    hdr, items, left = items_of(body)

    def fail(kind, why):
        cnt[kind + "_bad"] += 1
        if len(bad) < 30:
            bad.append((f"{va:#x}", kind, why))
    for h in hdr:
        if h.startswith("PDB "):
            cnt["header_ok"] += 1
            nm = R.procs.get(va)
            if nm is None or (nm + "(") not in h and not h.endswith(nm):
                fail("header", f"{h[:80]} vs {nm}")
                cnt["header_ok"] -= 1
    for a, kind, p, asm in items:
        if kind == "pre":
            if p.startswith("label "):
                ok = R.labels.get(a) == p[6:]
                cnt["label_ok" if ok else "label_bad"] += 1
                if not ok:
                    fail("label", f"{a:#x} {p}")
                continue
            m = re.fullmatch(r"line (\d+)", p) or re.fullmatch(r"(.+):(\d+)", p)
            if not m:
                fail("pre_unparsed", p)
                continue
            ln = int(m.groups()[-1])
            recs = R.lines.get(a, set())
            ok = any(l == ln for f, l in recs)
            if ok and len(m.groups()) == 2:
                tail = m.group(1).split("/", 1)[-1]
                ok = any(f.replace("\\", "/").endswith(tail) and l == ln for f, l in recs)
            cnt["line_ok" if ok else "line_bad"] += 1
            if not ok:
                fail("line", f"{a:#x} {p} recs={sorted(recs)[:3]}")
            continue
        if p.startswith("import "):
            mm = re.search(r"\[0x([0-9a-f]+)\]", asm or "")
            ok = mm is not None and ("__imp_" + p[7:]) in R.publics.get(int(mm.group(1), 16), ())
            cnt["import_ok" if ok else "import_bad"] += 1
            if not ok:
                fail("import", f"{a:#x} {p}")
        elif p.startswith("icall "):
            mt = re.search(r"\[ti (0x[0-9a-f]+)\]$", p)
            ok = mt is not None and R.callsites.get(a) == int(mt.group(1), 16)
            cnt["icall_ok" if ok else "icall_bad"] += 1
            if not ok:
                fail("icall", f"{a:#x} {p[:60]}")
        elif p.startswith("vcall "):
            mm = re.match(r"vcall (.+)::([^:\[]+?) \[slot", p)
            mt = re.search(r"\[ti (0x[0-9a-f]+)\]$", p)
            cls = R.class_name_of_mfunc(R.callsites[a]) if a in R.callsites else None
            ok = mm is not None and cls == mm.group(1) and mt is not None and R.callsites.get(a) == int(mt.group(1), 16)
            cnt["vcall_ok" if ok else "vcall_bad"] += 1
            if not ok:
                fail("vcall", f"{a:#x} {p[:80]} class={cls}")
        elif p.startswith("["):
            nm = p.split("]=", 1)[1]
            nm = re.sub(r"^&", "", nm)
            nm = re.sub(r"\[[^\]]*\]$", "", nm)
            nm = re.sub(r"\+0x[0-9a-f]+$", "", nm)
            names = nm[1:-1].split("|") if nm.startswith("{") else [nm]
            ok = all(n in R.frame.get(va, ()) for n in names)
            cnt["frame_ok" if ok else "frame_bad"] += 1
            if not ok:
                fail("frame", f"{a:#x} {p} known={sorted(R.frame.get(va, ()))[:6]}")
        elif p.startswith("0x"):
            hx, _, sym = p.partition("=")
            addr = int(hx, 16)
            sym = re.sub(r" \(.*\)$", "", sym)
            ok = False
            if sym.startswith("label "):
                ok = R.labels.get(addr) == sym[6:]
            elif cn2va.get(sym) == addr:
                ok = True
            else:
                mm = re.fullmatch(r"(.*?)\+0x([0-9a-f]+)", sym)
                base, off = (mm.group(1), int(mm.group(2), 16)) if mm else (sym, 0)
                names = set(base.split("|"))
                if names <= R.data.get(addr - off, set()):
                    ok = True
                elif off == 0 and R.publics.get(addr):
                    ok = True       # undecorated public (dbghelp spelling) at exactly ADDR
            cnt["data_ok" if ok else "data_bad"] += 1
            if not ok:
                fail("data", f"{a:#x} {p[:90]}")
        else:
            fail("note_unparsed", p[:80])


def main():
    t0 = time.time()
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import annotate_pdb as ap      # only for strip() (gate 1) and the shift control's producer (gate 3)
    R = Reader2()
    names_h = open(os.path.join(UNITS, "rfg_names.h"), encoding="utf-8").read()
    rev = dict(re.findall(r"^#define (\S+) (sub_[0-9A-F]{8})$", names_h, re.M))
    cn2va = {c: int(s[4:], 16) for c, s in rev.items()}
    flat = {}
    gen = os.path.join(ROOT, "gen")
    for u in sorted(os.listdir(gen)):
        if u.startswith("rfg_") and u.endswith(".c"):
            flat.update({int(k[4:], 16): v for k, v in ap.split_bodies(open(os.path.join(gen, u), encoding="utf-8").read()).items()})
    seen = collections.Counter()
    strip_bad, bad, cnt = [], [], collections.Counter()
    sample_body = None
    for p, va, body in tree_bodies(TREE):
        seen[va] += 1
        if ap.strip(body, rev) != flat.get(va):
            strip_bad.append(f"{va:#x}")
        elif sample_body is None and "// line" in body:
            sample_body = (va, body)
        check_body(R, va, body, cn2va, None, bad, cnt)
    missing = set(flat) - set(seen)
    dup = [v for v, c in seen.items() if c != 1]
    # gate 1 control: a one-character code change must not strip back
    va0, b0 = sample_body
    i = b0.index("esp")
    ctrl_strip = ap.strip(b0[:i] + "ebp" + b0[i + 3:], rev) != flat[va0]
    # gate 3: shift control on a sample
    P = ap.Pass(ROOT, shift=SHIFT)
    sample = sorted(flat)[::40]
    P.compute(sample)
    rel = ap.tree_path_fn(ROOT)
    scnt, sbad = collections.Counter(), []
    base_cnt = collections.Counter()
    P0 = ap.Pass(ROOT)
    P0.compute(sample)
    for P_, c_ in ((P, scnt), (P0, base_cnt)):
        for va in sample:
            res = P_.results.get(va)
            txt = ap.apply(flat[va], f"sub_{va:08X}", res, P_.A.cnames, rel, None)
            check_body(R, va, txt, cn2va, None, sbad if c_ is scnt else [], c_)
    shift_detect = {}
    for kind in ("line", "data", "icall", "vcall", "frame", "import"):
        ok0, bad1, ok1 = base_cnt[kind + "_ok"], scnt[kind + "_bad"], scnt[kind + "_ok"]
        detected = bad1 > 0 or ok1 <= ok0 * 0.1
        shift_detect[kind] = dict(unshifted_ok=ok0, unshifted_bad=base_cnt[kind + "_bad"], shifted_ok=ok1,
                                  shifted_bad=bad1, detected=detected)
    rec = dict(bodies=len(seen), flat_bodies=len(flat), missing=len(missing), duplicates=len(dup),
               strip_identical=len(seen) - len(strip_bad), strip_bad=strip_bad[:20], strip_control_caught=ctrl_strip,
               records=dict(sorted(cnt.items())), mismatches=bad, shift=SHIFT, shift_sample=len(sample),
               shift_control=shift_detect, seconds=round(time.time() - t0, 1))
    print(json.dumps(rec, indent=1))
    n_bad = sum(v for k, v in cnt.items() if k.endswith("_bad"))
    must = ("line", "data", "icall", "vcall", "frame")
    ok = (not missing and not dup and not strip_bad and ctrl_strip and n_bad == 0
          and all(shift_detect[k]["detected"] for k in must))
    # Receipt goes to work/, not into build_units: organize_rfg prunes files it did not produce
    # there, so writing it beside the units made every verify_all run fail organize idempotence.
    os.makedirs(os.path.join(ROOT, "work"), exist_ok=True)
    json.dump(rec, open(os.path.join(ROOT, "work", "verify_pdb_annot.json"), "w"), indent=1)
    print("VERIFY_PDB_ANNOT PASS" if ok else "VERIFY_PDB_ANNOT FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
