"""P8 identity allocation: every PDB procedure -> (obj module, source file) from the PDB itself.
Source file comes from the module's C13 DEBUG_S_LINES block whose range contains the proc start,
resolved through DEBUG_S_FILECHKSMS and the /names string table.
Usage: python -X utf8 -I pdb_alloc32.py <pe> <pdb> <feed_dir>
Reads feed/procs.tsv (from pdb_procs32.py), writes feed/allocation.tsv and feed/alloc_summary.json.
Exit 1 unless: every proc gets a module, and the control holds (a proc's start shifted into a
different module's line range must change its source file).
"""
import json, os, struct, sys
from bisect import bisect_right
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pdb_procs32 import MSF, dbi, read_pe, section_rvas, cstr  # noqa: E402  (main() is guarded below)


def named_streams(msf):
    s = msf.stream(1)
    o = 28
    blen = struct.unpack_from("<I", s, o)[0]
    buf = s[o + 4:o + 4 + blen]
    o += 4 + blen
    size, cap = struct.unpack_from("<II", s, o)
    o += 8
    npres = struct.unpack_from("<I", s, o)[0]
    pres = struct.unpack_from("<%dI" % npres, s, o + 4)
    o += 4 + 4 * npres
    ndel = struct.unpack_from("<I", s, o)[0]
    o += 4 + 4 * ndel
    out = {}
    for i in range(cap):
        if pres[i // 32] >> (i % 32) & 1:
            k, v = struct.unpack_from("<II", s, o)
            o += 8
            name = buf[k:buf.index(b"\0", k)].decode()
            out[name] = v
    return out


def main():
    pe, pdb, feed = sys.argv[1:4]
    base, entry, pe_secs = read_pe(pe)
    msf = MSF(pdb)
    info = dbi(msf)
    secs = section_rvas(msf, info, pe_secs)
    ns = named_streams(msf)
    names = msf.stream(ns["/names"])

    def strtab(off):
        return names[12 + off:names.index(b"\0", 12 + off)].decode("utf-8", "replace")

    s3 = msf.stream(3)
    modi_sz = struct.unpack_from("<i", s3, 24)[0]
    # per-module C11/C13 sizes from the modi records
    mod_rows = []
    o, end = 64, 64 + modi_sz
    while o < end:
        sn, symb, c11, c13 = struct.unpack_from("<HIII", s3, o + 34)
        name, p = cstr(s3, o + 64)
        obj, p = cstr(s3, p)
        mod_rows.append((sn, symb, c11, c13, name, obj))
        o = (p + 3) & ~3
    blocks = []  # (va_lo, va_hi, module_index, file)
    for mi, (sn, symb, c11, c13, mname, _obj) in enumerate(mod_rows):
        if not c13:
            continue
        st = msf.stream(sn)
        c = st[symb + c11:symb + c11 + c13]
        chk = {}
        q = 0
        subs = []
        while q + 8 <= len(c):
            kind, ln = struct.unpack_from("<II", c, q)
            subs.append((kind & 0x7FFFFFFF, c[q + 8:q + 8 + ln]))
            q += 8 + ((ln + 3) & ~3)
        for kind, b in subs:
            if kind == 0xF4:
                r = 0
                while r + 6 <= len(b):
                    noff, clen = struct.unpack_from("<IB", b, r)
                    chk[r] = strtab(noff)
                    r = (r + 6 + clen + 3) & ~3
        for kind, b in subs:
            if kind == 0xF2:
                off, seg, flags, csz = struct.unpack_from("<IHHI", b, 0)
                if not 1 <= seg <= len(secs):
                    continue
                va = base + secs[seg - 1][1] + off
                r = 12
                while r + 12 <= len(b):
                    fid, nlines, blen = struct.unpack_from("<III", b, r)
                    # CV_Line_t entries follow: (offset u32, flags u32), line = flags & 0xFFFFFF.
                    # The function's source position = the smallest line in its first file block
                    # (its opening line); used to lay functions out in original source order.
                    lines = [struct.unpack_from("<II", b, r + 12 + 8 * i)[1] & 0xFFFFFF
                             for i in range(nlines) if r + 12 + 8 * i + 8 <= len(b)]
                    first_line = min((x for x in lines if x and x != 0xFEEFEE), default=0)
                    blocks.append((va, va + csz, mi, chk.get(fid, "?"), first_line))
                    r += blen
                    break  # first file block of this contribution names the function's file
    blocks.sort()
    los = [b[0] for b in blocks]

    def lookup(va):
        i = bisect_right(los, va) - 1
        while i >= 0 and blocks[i][0] <= va:
            if va < blocks[i][1]:
                return blocks[i]
            i -= 1
        return None

    rows = []
    with open(os.path.join(feed, "procs.tsv"), encoding="utf-8") as f:
        f.readline()
        for line in f:
            va, size, kind, name, module, flags = line.rstrip("\n").split("\t")
            rows.append((int(va, 16), int(size), kind, name, module))
    # Compiland source per module: the S_ENVBLOCK "src" value (the file cl.exe compiled to make
    # this object). A procedure without C13 lines was emitted by that compilation, so that file
    # is its placement. Import modules ("Import:X.dll") have no compiland; their obj field is the
    # import library the linker took the thunks from. (Class-based placement was calibrated by
    # leave-one-out and REFUSED: special members 0.98549, Wilson 0.98428 < 0.99.)
    comp = {}
    for sn, symb, c11, c13, mname, mobj in mod_rows:
        src = ""
        st = msf.stream(sn)[:symb]
        k = 4
        while k + 4 <= len(st):
            reclen, kind = struct.unpack_from("<HH", st, k)
            if reclen < 2:
                break
            if kind == 0x113D:
                kv = [v.decode("utf-8", "replace") for v in st[k + 5:k + 2 + reclen].split(b"\0")]
                env = {kv[i]: kv[i + 1] for i in range(0, len(kv) - 1, 2)}
                src = env.get("src", "")
                # Havok's build ran cl with paths relative to its working directory: "src" is
                # relative there, and "cwd" in the same block is what it is relative to.
                if src and not (len(src) > 2 and src[1] == ":") and not src.startswith(("\\\\", "/")):
                    cwd = env.get("cwd", "")
                    src = (cwd.rstrip("\\/") + "\\" + src) if cwd else ""
                break
            k += 2 + reclen
        if src:
            comp[mname] = (src.replace("/", "\\").lower(), "PDB_COMPILAND_SRC")
        elif mname.startswith("Import:") and mobj:
            comp[mname] = (mobj.lower(), "PDB_IMPORT_LIB")
    stats = Counter()
    out = []
    for va, size, kind, name, module in rows:
        b = lookup(va)
        src = b[3] if b else ""
        same_mod = b is not None and mod_rows[b[2]][4] == module
        stats["with_source"] += bool(b)
        stats["line_module_equals_symbol_module"] += same_mod
        if src:
            place, pev = src, "PDB_LINES"
        else:
            place, pev = comp.get(module, ("", "NONE"))
        stats[pev] += 1
        out.append((va, size, kind, name, module, src, place, pev, b[4] if b else 0))
    # control: move one proc's start into another module's line block and require a different file
    a = next(r for r in out if r[5])
    other = next(bl for bl in blocks if bl[3] != a[5] and mod_rows[bl[2]][4] != a[4])
    moved = lookup(other[0])
    ctrl_ok = moved is not None and moved[3] != a[5]
    with open(os.path.join(feed, "allocation.tsv"), "w", encoding="utf-8") as w:
        w.write("va\tsize\tkind\tname\tobj_module\tsource_file\tplacement_file\tplacement_evidence\tsource_line\n")
        for r in out:
            w.write(f"{r[0]:#010x}\t{r[1]}\t{r[2]}\t{r[3]}\t{r[4]}\t{r[5]}\t{r[6]}\t{r[7]}\t{r[8]}\n")
    src_files = Counter(r[5] for r in out if r[5])
    summ = dict(procs=len(out), with_obj_module=sum(1 for r in out if r[4]),
                with_source_file=stats["with_source"],
                line_module_equals_symbol_module=stats["line_module_equals_symbol_module"],
                placement={k: stats[k] for k in ("PDB_LINES", "PDB_COMPILAND_SRC", "PDB_IMPORT_LIB", "NONE")},
                distinct_source_files=len(src_files), distinct_obj_modules=len({r[4] for r in out}),
                line_blocks=len(blocks), named_streams=sorted(ns),
                control=dict(proc=a[3], file=a[5], moved_to=hex(other[0]), got=moved[3] if moved else None, ok=ctrl_ok),
                top_files=src_files.most_common(8))
    json.dump(summ, open(os.path.join(feed, "alloc_summary.json"), "w"), indent=1)
    print(json.dumps(summ, indent=1))
    ok = ctrl_ok and summ["with_obj_module"] == len(out) and stats["NONE"] == 0
    print("PDB_ALLOC DONE" if ok else "PDB_ALLOC REFUSE")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
