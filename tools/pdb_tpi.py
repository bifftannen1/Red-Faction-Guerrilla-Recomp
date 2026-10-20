"""rfg.pdb reader for the decomp toolkit: MSF 7.00 (any block size, multi-block directory map), DBI
module list, per-module procedure symbols WITH their type index, publics, and the full TPI type graph.

Pure Python, read-only. The TPI parser covers every leaf this PDB uses for layout and signatures
(class/struct/union/enum with forward refs resolved by unique name, field lists with LF_INDEX
continuation, pointers, modifiers, arrays, bitfields, procedures, member functions, arg lists,
vtable shapes). `Tpi.unknown_leaves` counts leaves it skipped so a caller can refuse on gaps.
"""
import struct
from collections import Counter

PROC_KINDS = {0x110F: "LPROC32", 0x1110: "GPROC32", 0x1146: "LPROC32_ID", 0x1147: "GPROC32_ID"}
S_PUB32 = 0x110E
S_GDATA32, S_LDATA32 = 0x110D, 0x110C


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


def numeric(b, o):
    """CodeView numeric leaf -> (value, next offset)."""
    v = struct.unpack_from("<H", b, o)[0]
    if v < 0x8000:
        return v, o + 2
    fmt = {0x8000: "<b", 0x8001: "<h", 0x8002: "<H", 0x8003: "<i", 0x8004: "<I", 0x8009: "<q", 0x800A: "<Q",
           0x8005: "<f", 0x8006: "<d"}.get(v)
    if fmt is None:
        raise ValueError("numeric leaf %#x" % v)
    n = struct.calcsize(fmt)
    return struct.unpack_from(fmt, b, o + 2)[0], o + 2 + n


# ---- basic types --------------------------------------------------------------------------------
BASIC = {0x03: ("void", 0), 0x08: ("int32_t", 4), 0x10: ("int8_t", 1), 0x20: ("uint8_t", 1), 0x68: ("int8_t", 1),
         0x69: ("uint8_t", 1), 0x70: ("char", 1), 0x71: ("wchar_t", 2), 0x7A: ("char16_t", 2),
         0x7B: ("char32_t", 4), 0x11: ("int16_t", 2), 0x21: ("uint16_t", 2), 0x72: ("int16_t", 2),
         0x73: ("uint16_t", 2), 0x12: ("int32_t", 4), 0x22: ("uint32_t", 4), 0x74: ("int32_t", 4),
         0x75: ("uint32_t", 4), 0x13: ("int64_t", 8), 0x23: ("uint64_t", 8), 0x76: ("int64_t", 8),
         0x77: ("uint64_t", 8), 0x40: ("float", 4), 0x41: ("double", 8), 0x42: ("long double", 10),
         0x30: ("bool", 1), 0x31: ("uint16_t", 2), 0x32: ("uint32_t", 4), 0x33: ("uint64_t", 8)}


class Tpi:
    def __init__(self, data):
        ver, hsz, self.ti_begin, self.ti_end, nbytes = struct.unpack_from("<IIIII", data, 0)
        self.recs = {}       # ti -> (leaf, dict)
        self.unknown_leaves = Counter()
        o, ti = hsz, self.ti_begin
        while o < hsz + nbytes:
            ln, leaf = struct.unpack_from("<HH", data, o)
            body = data[o + 4:o + 2 + ln]
            try:
                self.recs[ti] = (leaf, self._parse(leaf, body))
            except Exception as e:  # noqa: BLE001 -- counted, never silent
                self.unknown_leaves["parse_error_%#x" % leaf] += 1
                self.recs[ti] = (leaf, {"error": str(e)})
            o += 2 + ln
            ti += 1
        self.count = ti - self.ti_begin
        # forward-ref resolution: unique name (else name) -> defining record
        self.defs = {}
        for t, (leaf, r) in self.recs.items():
            if leaf in (0x1504, 0x1505, 0x1506, 0x1507, 0x1519) and not r.get("fwd"):
                k = r.get("unique") or r.get("name")
                self.defs.setdefault(k, t)
        self.by_name = {}
        for t, (leaf, r) in self.recs.items():
            if leaf in (0x1504, 0x1505, 0x1506, 0x1507, 0x1519) and not r.get("fwd"):
                self.by_name.setdefault(r["name"], []).append(t)

    # -- record parsing --
    def _parse(self, leaf, b):
        if leaf == 0x1001:
            t, attr = struct.unpack_from("<IH", b, 0)
            return dict(type=t, const=bool(attr & 1), volatile=bool(attr & 2))
        if leaf == 0x1002:
            t, attr = struct.unpack_from("<II", b, 0)
            return dict(type=t, ptrtype=attr & 0x1F, mode=(attr >> 5) & 7, size=(attr >> 13) & 0x3F,
                        const=bool(attr & 0x400))
        if leaf == 0x1008:
            rv, cc, fa, pc, al = struct.unpack_from("<IBBHI", b, 0)
            return dict(rv=rv, cc=cc, parmcount=pc, arglist=al)
        if leaf == 0x1009:
            rv, cls, this, cc, fa, pc, al, adj = struct.unpack_from("<IIIBBHIi", b, 0)
            return dict(rv=rv, cls=cls, this=this, cc=cc, parmcount=pc, arglist=al, thisadjust=adj)
        if leaf == 0x1201:
            n = struct.unpack_from("<I", b, 0)[0]
            return dict(args=list(struct.unpack_from("<%dI" % n, b, 4)))
        if leaf == 0x1203:
            return dict(fields=self._fieldlist(b))
        if leaf == 0x1205:
            t, ln, pos = struct.unpack_from("<IBB", b, 0)
            return dict(type=t, length=ln, pos=pos)
        if leaf == 0x1503:
            et, it = struct.unpack_from("<II", b, 0)
            size, o = numeric(b, 8)
            name, _ = cstr(b, o)
            return dict(elem=et, idx=it, size=size, name=name)
        if leaf in (0x1504, 0x1505, 0x1519):
            cnt, prop, fl, der, vsh = struct.unpack_from("<HHIII", b, 0)
            size, o = numeric(b, 16)
            name, o = cstr(b, o)
            uniq = cstr(b, o)[0] if prop & 0x200 and o < len(b) else ""
            return dict(count=cnt, prop=prop, fwd=bool(prop & 0x80), field=fl, vshape=vsh, size=size, name=name, unique=uniq,
                        kind={0x1504: "class", 0x1505: "struct", 0x1519: "interface"}[leaf])
        if leaf == 0x1506:
            cnt, prop, fl = struct.unpack_from("<HHI", b, 0)
            size, o = numeric(b, 8)
            name, o = cstr(b, o)
            uniq = cstr(b, o)[0] if prop & 0x200 and o < len(b) else ""
            return dict(count=cnt, prop=prop, fwd=bool(prop & 0x80), field=fl, size=size, name=name, unique=uniq, kind="union")
        if leaf == 0x1507:
            cnt, prop, ut, fl = struct.unpack_from("<HHII", b, 0)
            name, o = cstr(b, 12)
            uniq = cstr(b, o)[0] if prop & 0x200 and o < len(b) else ""
            return dict(count=cnt, fwd=bool(prop & 0x80), utype=ut, field=fl, name=name, unique=uniq, kind="enum")
        if leaf == 0x000A:
            n = struct.unpack_from("<H", b, 0)[0]
            return dict(count=n)
        if leaf == 0x1206:
            return dict()
        self.unknown_leaves["%#x" % leaf] += 1
        return dict()

    def _fieldlist(self, b):
        out, o = [], 0
        while o < len(b):
            if b[o] >= 0xF0:
                o += b[o] & 0x0F
                continue
            k = struct.unpack_from("<H", b, o)[0]
            if k == 0x150D:   # LF_MEMBER
                attr, t = struct.unpack_from("<HI", b, o + 2)
                off, p = numeric(b, o + 8)
                name, p = cstr(b, p)
                out.append(dict(k="member", type=t, offset=off, name=name, access=attr & 3))
            elif k == 0x1400:  # LF_BCLASS
                attr, t = struct.unpack_from("<HI", b, o + 2)
                off, p = numeric(b, o + 8)
                out.append(dict(k="base", type=t, offset=off))
            elif k in (0x1401, 0x1402):  # LF_VBCLASS / LF_IVBCLASS
                attr, t, vbt = struct.unpack_from("<HII", b, o + 2)
                _, p = numeric(b, o + 12)
                _, p = numeric(b, p)
                out.append(dict(k="vbase", type=t, indirect=k == 0x1402))
            elif k == 0x1502:  # LF_ENUMERATE
                attr = struct.unpack_from("<H", b, o + 2)[0]
                val, p = numeric(b, o + 4)
                name, p = cstr(b, p)
                out.append(dict(k="enumerate", value=val, name=name))
            elif k == 0x1404:  # LF_INDEX
                t = struct.unpack_from("<I", b, o + 4)[0]
                out.append(dict(k="index", type=t))
                p = o + 8
            elif k == 0x150E:  # LF_STMEMBER
                attr, t = struct.unpack_from("<HI", b, o + 2)
                name, p = cstr(b, o + 8)
                out.append(dict(k="static", type=t, name=name))
            elif k == 0x150F:  # LF_METHOD
                cnt, ml = struct.unpack_from("<HI", b, o + 2)
                name, p = cstr(b, o + 8)
                out.append(dict(k="method", count=cnt, mlist=ml, name=name))
            elif k == 0x1510:  # LF_NESTTYPE
                t = struct.unpack_from("<I", b, o + 4)[0]
                name, p = cstr(b, o + 8)
                out.append(dict(k="nested", type=t, name=name))
            elif k == 0x1409:  # LF_VFUNCTAB
                t = struct.unpack_from("<I", b, o + 4)[0]
                out.append(dict(k="vfptr", type=t))
                p = o + 8
            elif k == 0x1511:  # LF_ONEMETHOD
                attr, t = struct.unpack_from("<HI", b, o + 2)
                mprop = (attr >> 2) & 7
                p = o + 8
                vbo = None
                if mprop in (4, 6):
                    vbo = struct.unpack_from("<I", b, p)[0]
                    p += 4
                name, p = cstr(b, p)
                out.append(dict(k="onemethod", type=t, name=name, mprop=mprop, vbaseoff=vbo))
            elif k == 0x150C:  # LF_FRIENDFCN
                t = struct.unpack_from("<I", b, o + 4)[0]
                name, p = cstr(b, o + 8)
                out.append(dict(k="friendfcn", type=t, name=name))
            elif k == 0x140B:  # LF_FRIENDCLS
                p = o + 8
            elif k == 0x1405:  # LF_VFUNCOFF
                p = o + 12
            else:
                raise ValueError("fieldlist sub-leaf %#x" % k)
            o = p
        return out

    # -- queries --
    def rec(self, ti):
        return self.recs.get(ti, (None, {}))

    def resolve(self, ti):
        """Forward reference -> defining type index (same index when already a definition)."""
        leaf, r = self.rec(ti)
        if leaf in (0x1504, 0x1505, 0x1506, 0x1507, 0x1519) and r.get("fwd"):
            return self.defs.get(r.get("unique") or r.get("name"), ti)
        return ti

    def strip(self, ti):
        """Remove modifiers (const/volatile)."""
        while ti >= 0x1000:
            leaf, r = self.rec(ti)
            if leaf != 0x1001:
                break
            ti = r["type"]
        return ti

    def sizeof(self, ti):
        ti = self.resolve(self.strip(ti))
        if ti < 0x1000:
            mode = (ti >> 8) & 0xF
            if mode:
                return 8 if mode == 6 else 4
            return BASIC.get(ti & 0xFF, ("?", 0))[1]
        leaf, r = self.rec(ti)
        if leaf == 0x1002:
            return r["size"] or 4
        if leaf in (0x1503, 0x1504, 0x1505, 0x1506, 0x1519):
            return r["size"]
        if leaf == 0x1507:
            return self.sizeof(r["utype"])
        if leaf == 0x1205:
            return self.sizeof(r["type"])
        return 0

    def fields(self, ti):
        """Flattened field list of a UDT (LF_INDEX continuations followed)."""
        ti = self.resolve(ti)
        leaf, r = self.rec(ti)
        out, fl, seen = [], r.get("field", 0), set()
        while fl and fl not in seen:
            seen.add(fl)
            lf, fr = self.rec(fl)
            nxt = 0
            for f in fr.get("fields", []):
                if f["k"] == "index":
                    nxt = f["type"]
                else:
                    out.append(f)
            fl = nxt
        return out

    def name(self, ti, depth=0):
        """C-ish spelling of a type (for prototypes and reports)."""
        if depth > 12:
            return "void"
        if ti < 0x1000:
            mode = (ti >> 8) & 0xF
            base = BASIC.get(ti & 0xFF, ("uint32_t", 4))[0]
            return base + " *" if mode else base
        leaf, r = self.rec(ti)
        if leaf == 0x1001:
            return ("const " if r["const"] else "") + self.name(r["type"], depth + 1)
        if leaf == 0x1002:
            star = "&" if r["mode"] in (1, 4) else "*"
            return self.name(r["type"], depth + 1) + " " + star
        if leaf in (0x1504, 0x1505, 0x1506, 0x1507, 0x1519):
            return r["name"]
        if leaf == 0x1503:
            return self.name(r["elem"], depth + 1) + "[]"
        if leaf in (0x1008, 0x1009):
            return "fn"
        if leaf == 0x1205:
            return self.name(r["type"], depth + 1)
        return "uint32_t"

    def is_float(self, ti):
        ti = self.strip(ti)
        return ti < 0x1000 and not (ti >> 8) & 0xF and (ti & 0xFF) in (0x40, 0x41, 0x42)

    def is_pointer(self, ti):
        ti = self.strip(ti)
        if ti < 0x1000:
            return bool((ti >> 8) & 0xF)
        return self.rec(ti)[0] == 0x1002

    def pointee(self, ti):
        ti = self.strip(ti)
        if ti < 0x1000:
            return ti & 0xFF
        return self.rec(ti)[1].get("type", 0)

    def is_udt(self, ti):
        ti = self.resolve(self.strip(ti))
        return ti >= 0x1000 and self.rec(ti)[0] in (0x1504, 0x1505, 0x1506, 0x1519)


def walk_syms(buf, start, cb):
    o = start
    while o + 4 <= len(buf):
        reclen, kind = struct.unpack_from("<HH", buf, o)
        if reclen < 2:
            break
        cb(kind, buf, o + 4, o + 2 + reclen)
        o += 2 + reclen


class Pdb:
    def __init__(self, pdb_path, image_base=0x400000):
        self.msf = MSF(pdb_path)
        self.base = image_base
        s = self.msf.stream(3)
        f = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", s, 0)
        self.machine = f[18]
        self.symrec = f[7]
        modi_sz, sc_sz, secmap_sz, fi_sz, tsm_sz, dbg_sz, ec_sz = f[9], f[10], f[11], f[12], f[13], f[15], f[16]
        o, end, self.mods = 64, 64 + modi_sz, []
        while o < end:
            sn = struct.unpack_from("<H", s, o + 34)[0]
            symbytes = struct.unpack_from("<I", s, o + 36)[0]
            name, p = cstr(s, o + 64)
            obj, p = cstr(s, p)
            self.mods.append(dict(stream=sn, symbytes=symbytes, name=name, obj=obj))
            o = (p + 3) & ~3
        dbg_off = 64 + modi_sz + sc_sz + secmap_sz + fi_sz + tsm_sz + ec_sz
        dbg = struct.unpack_from("<%dH" % (dbg_sz // 2), s, dbg_off)
        sh = self.msf.stream(dbg[5])
        self.sections = [struct.unpack_from("<8sII", sh, 40 * i) for i in range(len(sh) // 40)]
        self._tpi = None

    def va_of(self, seg, off):
        if not 1 <= seg <= len(self.sections):
            return None
        return self.base + self.sections[seg - 1][2] + off

    @property
    def tpi(self):
        if self._tpi is None:
            self._tpi = Tpi(self.msf.stream(2))
        return self._tpi

    def procs(self):
        """[(va, size, name, typind, kind, module)] for every procedure record."""
        out = []
        for m in self.mods:
            st = self.msf.stream(m["stream"])

            def on(kind, b, o, end, mod=m["name"]):
                if kind in PROC_KINDS:
                    plen = struct.unpack_from("<I", b, o + 12)[0]
                    typ = struct.unpack_from("<I", b, o + 24)[0]
                    off, seg = struct.unpack_from("<IH", b, o + 28)
                    name, _ = cstr(b, o + 35)
                    out.append((self.va_of(seg, off), plen, name, typ, PROC_KINDS[kind], mod))
            walk_syms(st[:m["symbytes"]], 4, on)
        return out

    def globals_data(self):
        """[(va, name, typind)] from module S_GDATA32/S_LDATA32 and the global symbol stream."""
        out = []

        def on(kind, b, o, end):
            if kind in (S_GDATA32, S_LDATA32):
                typ, off, seg = struct.unpack_from("<IIH", b, o)
                name, _ = cstr(b, o + 10)
                va = self.va_of(seg, off)
                if va is not None:
                    out.append((va, name, typ))
        for m in self.mods:
            st = self.msf.stream(m["stream"])
            walk_syms(st[:m["symbytes"]], 4, on)
        walk_syms(self.msf.stream(self.symrec), 0, on)
        return out

    def publics(self):
        out = []

        def on(kind, b, o, end):
            if kind == S_PUB32:
                flags, off, seg = struct.unpack_from("<IIH", b, o)
                name, _ = cstr(b, o + 10)
                out.append((self.va_of(seg, off), flags, name))
        walk_syms(self.msf.stream(self.symrec), 0, on)
        return out
