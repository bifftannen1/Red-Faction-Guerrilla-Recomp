"""Function list: every procedure in an x86 PE32's matching PDB as (VA, size, name, kind, module).
Reads MSF 7.00 directly (any block size, multi-block directory map), the DBI module list,
each module's symbol stream (S_GPROC32/S_LPROC32 and *_ID, plus thunks), the original
section headers from the DBI optional debug header, and publics from the symbol-record stream.

Usage: python -X utf8 -I pdb_procs32.py <pe> <pdb> <out_dir>
Writes: procs.tsv, publics.tsv, summary.json.
Refuses (exit 1) unless the positive control holds: the PE AddressOfEntryPoint must be the start
of exactly one procedure or public, and a shifted copy of the section table (+0x1000) must move it.
"""
import json, os, struct, sys
from collections import Counter

S_PUB32 = 0x110E
PROC_KINDS = {0x110F: "LPROC32", 0x1110: "GPROC32", 0x1146: "LPROC32_ID", 0x1147: "GPROC32_ID",
              0x1153: "LPROC32_DPC", 0x1154: "LPROC32_DPC_ID"}
S_THUNK32 = 0x1102
S_END = 0x0006


class MSF:
    def __init__(self, path):
        self.f = open(path, "rb")
        sb = self.f.read(56)
        if sb[:24] != b"Microsoft C/C++ MSF 7.00":
            raise SystemExit("REFUSE: not MSF 7.00")
        self.bs, _, self.nblocks, dir_bytes, _, map_addr = struct.unpack_from("<IIIIII", sb, 32)
        ndir = -(-dir_bytes // self.bs)
        nmap = -(-ndir * 4 // self.bs)
        self.f.seek(map_addr * self.bs)
        mapbuf = self.f.read(nmap * self.bs)
        dir_ids = struct.unpack_from("<%dI" % ndir, mapbuf, 0)
        d = b"".join(self._blk(i) for i in dir_ids)[:dir_bytes]
        n = struct.unpack_from("<I", d, 0)[0]
        self.sizes = list(struct.unpack_from("<%dI" % n, d, 4))
        pos = 4 + 4 * n
        self.blocks = []
        for s in self.sizes:
            k = 0 if s == 0xFFFFFFFF else -(-s // self.bs)
            self.blocks.append(struct.unpack_from("<%dI" % k, d, pos))
            pos += 4 * k

    def _blk(self, i):
        self.f.seek(i * self.bs)
        return self.f.read(self.bs)

    def stream(self, i):
        if i == 0xFFFF or i >= len(self.sizes) or self.sizes[i] == 0xFFFFFFFF:
            return b""
        return b"".join(self._blk(b) for b in self.blocks[i])[:self.sizes[i]]


def cstr(b, o):
    e = b.index(b"\0", o)
    return b[o:e].decode("utf-8", "replace"), e + 1


def read_pe(path):
    b = open(path, "rb").read()
    lf = struct.unpack_from("<I", b, 0x3C)[0]
    nsec, optsz = struct.unpack_from("<H", b, lf + 6)[0], struct.unpack_from("<H", b, lf + 20)[0]
    opt = lf + 24
    entry = struct.unpack_from("<I", b, opt + 16)[0]
    base = struct.unpack_from("<I", b, opt + 28)[0]
    secs = []
    for i in range(nsec):
        name, vsz, va = struct.unpack_from("<8sII", b, opt + optsz + 40 * i)
        secs.append((name.rstrip(b"\0").decode(), va, vsz))
    return base, entry, secs


def dbi(msf):
    s = msf.stream(3)
    (sig, ver, age, gsi, bld, psi, pdbdll, symrec, pdbbld, modi_sz, sc_sz, secmap_sz, fi_sz,
     tsm_sz, mfc, dbg_sz, ec_sz, flags, machine, pad) = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", s, 0)
    hdr = 64
    mods = []
    o = hdr
    end = hdr + modi_sz
    while o < end:
        sn = struct.unpack_from("<H", s, o + 34)[0]
        symbytes = struct.unpack_from("<I", s, o + 36)[0]
        name, p = cstr(s, o + 64)
        obj, p = cstr(s, p)
        mods.append(dict(stream=sn, symbytes=symbytes, name=name, obj=obj))
        o = (p + 3) & ~3
    dbg_off = hdr + modi_sz + sc_sz + secmap_sz + fi_sz + tsm_sz + ec_sz
    dbg = struct.unpack_from("<%dH" % (dbg_sz // 2), s, dbg_off)
    return dict(machine=machine, symrec=symrec, mods=mods, dbg=dbg, age=age)


def section_rvas(msf, dbginfo, pe_secs):
    # dbg[5] = section header stream (original); fall back to the PE's own table
    sh = msf.stream(dbginfo["dbg"][5]) if len(dbginfo["dbg"]) > 5 else b""
    rvas = []
    for i in range(len(sh) // 40):
        name, vsz, va = struct.unpack_from("<8sII", sh, 40 * i)
        rvas.append((name.rstrip(b"\0").decode(), va, vsz))
    return rvas or pe_secs


def walk_syms(buf, start, cb):
    o = start
    while o + 4 <= len(buf):
        reclen, kind = struct.unpack_from("<HH", buf, o)
        if reclen < 2:
            break
        cb(kind, buf, o + 4, o + 2 + reclen)
        o += 2 + reclen


def main():
    pe_path, pdb_path, out = sys.argv[1:4]
    os.makedirs(out, exist_ok=True)
    base, entry, pe_secs = read_pe(pe_path)
    msf = MSF(pdb_path)
    info = dbi(msf)
    secs = section_rvas(msf, info, pe_secs)

    def va_of(seg, off, table=secs):
        if not 1 <= seg <= len(table):
            return None
        return base + table[seg - 1][1] + off

    procs = []

    def on_proc_factory(modname, table):
        def on(kind, b, o, end):
            if kind in PROC_KINDS:
                plen = struct.unpack_from("<I", b, o + 12)[0]
                off, seg = struct.unpack_from("<IH", b, o + 28)
                flags = b[o + 34]
                name, _ = cstr(b, o + 35)
                procs.append((va_of(seg, off, table), plen, name, PROC_KINDS[kind], modname, flags))
            elif kind == S_THUNK32:
                off, seg, tlen = struct.unpack_from("<IHH", b, o + 12)
                name, _ = cstr(b, o + 21)
                procs.append((va_of(seg, off, table), tlen, name, "THUNK32", modname, 0))
        return on

    def collect(table):
        procs.clear()
        for m in info["mods"]:
            st = msf.stream(m["stream"])
            walk_syms(st[:m["symbytes"]], 4, on_proc_factory(m["name"], table))
        return list(procs)

    rows = collect(secs)
    pubs = []

    def on_pub(kind, b, o, end):
        if kind == S_PUB32:
            flags, off, seg = struct.unpack_from("<IIH", b, o)
            name, _ = cstr(b, o + 10)
            pubs.append((va_of(seg, off), flags, name))
    walk_syms(msf.stream(info["symrec"]), 0, on_pub)

    # positive control: entry point must be a proc start; shifted table must move it
    ep = base + entry
    ep_procs = [r for r in rows if r[0] == ep]
    ep_pubs = [p for p in pubs if p[0] == ep]
    shifted = [(n, va + 0x1000, vs) for n, va, vs in secs]
    rows_shift = collect(shifted)
    shift_hits = [r for r in rows_shift if r[0] == ep]
    control_ok = len(ep_procs) == 1 and not shift_hits

    with open(os.path.join(out, "procs.tsv"), "w", encoding="utf-8") as w:
        w.write("va\tsize\tkind\tname\tmodule\tflags\n")
        for va, sz, name, kind, mod, fl in sorted(rows, key=lambda r: (r[0] or 0, r[2])):
            w.write(f"{va:#010x}\t{sz}\t{kind}\t{name}\t{mod}\t{fl:#04x}\n" if va is not None
                    else f"NONE\t{sz}\t{kind}\t{name}\t{mod}\t{fl:#04x}\n")
    with open(os.path.join(out, "publics.tsv"), "w", encoding="utf-8") as w:
        w.write("va\tflags\tname\n")
        for va, fl, name in sorted(pubs, key=lambda p: (p[0] or 0, p[2])):
            w.write(f"{va:#010x}\t{fl:#x}\t{name}\n" if va is not None else f"NONE\t{fl:#x}\t{name}\n")

    text = next(s for s in secs if s[0] == ".text")
    t0, t1 = base + text[1], base + text[1] + text[2]
    starts = Counter(r[0] for r in rows if r[0] is not None)
    in_text = [r for r in rows if r[0] is not None and t0 <= r[0] < t1]
    uniq_text_starts = {r[0] for r in in_text}
    covered = sum(sz for va, sz in {(r[0], r[1]) for r in in_text})
    summ = dict(
        pe=pe_path, pdb=pdb_path, machine=hex(info["machine"]), dbi_age=info["age"], block_size=msf.bs,
        modules=len(info["mods"]), sections=[s[0] for s in secs],
        proc_records=len(rows), proc_kinds=dict(Counter(r[3] for r in rows)),
        proc_va_none=sum(1 for r in rows if r[0] is None),
        procs_in_text=len(in_text), unique_text_starts=len(uniq_text_starts),
        starts_with_multiple_records=sum(1 for v in starts.values() if v > 1),
        text_bytes=text[2], text_bytes_covered_by_proc_extents_sum=covered,
        publics=len(pubs), publics_function_flag=sum(1 for p in pubs if p[1] & 2),
        entry_va=hex(ep), entry_proc=[r[2] for r in ep_procs], entry_public=[p[2] for p in ep_pubs],
        control_shifted_table_hits=len(shift_hits), control_ok=control_ok)
    json.dump(summ, open(os.path.join(out, "summary.json"), "w"), indent=1)
    print(json.dumps(summ, indent=1))
    if not control_ok:
        print("PDB_PROCS REFUSE: positive control failed")
        sys.exit(1)
    print("PDB_PROCS DONE")


if __name__ == "__main__":
    main()
