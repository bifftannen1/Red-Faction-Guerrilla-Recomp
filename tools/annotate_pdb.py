"""Exact PDB annotation of the lifted RFG PC code (no decompilation): everything rfg.pdb records at an
address is attached to the lifted statement at exactly that address, as comments, and every function
gets a real C identifier through a #define alias, so the compiled objects do not change at all.

What is applied (each from a PDB record at exactly the annotated address, nothing inferred from names):
  names   `void sub_XXXXXXXX(void)` and every `sub_XXXXXXXX` reference -> a C identifier derived from
          the PDB procedure name (rules in cname_of); a name shared by two procedures (overloads,
          sanitiser collisions) or equal to any identifier/macro the build sees gets `_<VA>`. The
          build gets `#define <cname> sub_XXXXXXXX` (rfg_names.h), so link symbols, the dispatch table
          and every object stay byte-identical.
  lines   every C13 line record (all lines of every block): `// line N` (or `// <path>:N` when the
          line's file is not the function's own file) before the statement whose instruction starts
          at the record's address.
  data    every image address in an operand (memory displacement or immediate) -> the S_GDATA32 /
          S_LDATA32 / S_PUB32 / procedure / S_LABEL32 containing it: `0xADDR=name+off`; a data
          symbol contains an address only within [va, va + sizeof(type)) from TPI, a public only at
          its exact address.
  frame   S_BPREL32 / S_REGREL32 per procedure -> `[esp+d]`/`[ebp+d]` operands named, only where the
          stack and frame pointers are proven fixed: a forward dataflow over the lifted instructions
          (push/pop/sub/add/and esp, mov ebp,esp, leave, callee `ret N` measured from the callee's
          own body, else its PDB type) where every join must agree and every `ret` / tail jump must
          see esp at its entry value; a function failing either check gets no frame names.
          Base per record: FPO functions use the entry esp, ebp frames ebp, `and esp` frames the
          aligned esp; every record whose base the function does not establish is counted, not used.
  calls   S_CALLSITEINFO at an indirect call -> its prototype; `call [IAT]` -> the import's public;
          a `call reg` whose register was loaded in the same block by `mov reg, [vptr + N]` with vptr
          loaded by `mov vptr, [obj (+k)]` -> the virtual method at slot N of the call type's class
          (TPI vtable layout), only when that method's type index equals the call-site type index.
  labels  S_LABEL32 (except compiler `$` labels) at their instruction.
  header  the procedure's PDB type (calling convention, prototype with parameter names) and its frame
          records, as a comment block at the top of each body.

Modes
  build   compute everything for all bodies of <gen>, write config/pdb_annot/cnames.tsv and the
          coverage receipt (config/pdb_annot/receipt.json); the gates below run on scratch copies.
  (lib)   organize_rfg.py --annotate config/pdb_annot uses Annotator.annotate()/strip().
  verify  re-read the annotated named tree, strip it back to the flat bodies (byte-identical), and
          re-check every annotation against a SECOND PDB reader (probes/pdb_procs32.py MSF code,
          independent symbol walk); a copy of the facts shifted by +SHIFT bytes must fail.
Usage: python -X utf8 -P tools/annotate_pdb.py build <rfg_pc_recomp>
       python -X utf8 -P tools/annotate_pdb.py verify <rfg_pc_recomp> <gen_named> [--shift-control]
Markers: ANNOTATE_PDB BUILD DONE / ANNOTATE_PDB VERIFY PASS
"""
import bisect, collections, ctypes, hashlib, json, os, pickle, re, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from pdb_tpi import Pdb, walk_syms, cstr  # noqa: E402

CV_REG = {17: "eax", 18: "ecx", 19: "edx", 20: "ebx", 21: "esp", 22: "ebp", 23: "esi", 24: "edi",
          1: "al", 2: "cl", 3: "dl", 4: "bl", 9: "ax", 10: "cx", 11: "dx", 12: "bx", 13: "sp", 14: "bp",
          15: "si", 16: "di", 128: "st0", 154: "xmm0", 155: "xmm1", 156: "xmm2", 157: "xmm3", 158: "xmm4",
          159: "xmm5", 160: "xmm6", 161: "xmm7"}
CC_NAME = {0x00: "__cdecl", 0x04: "__fastcall", 0x07: "__stdcall", 0x0B: "__thiscall", 0x0D: "__clrcall"}
PROC_KINDS = (0x110F, 0x1110, 0x1146, 0x1147)
C_KEYWORDS = set("""auto break case char const continue default do double else enum extern float for goto if inline
int long register restrict return short signed sizeof static struct switch typedef union unsigned void volatile
while _Bool _Complex _Imaginary alignas alignof and and_eq asm bitand bitor bool catch char16_t char32_t class
compl constexpr const_cast decltype delete dynamic_cast explicit export false friend mutable namespace new
noexcept not not_eq nullptr operator or or_eq private protected public reinterpret_cast static_assert
static_cast template this thread_local throw true try typeid typename using virtual wchar_t xor xor_eq main
_Alignas _Alignof _Atomic _Generic _Noreturn _Static_assert _Thread_local""".split())
OPS = [("operator new[]", "op_new_arr"), ("operator delete[]", "op_delete_arr"), ("operator new", "op_new"),
       ("operator delete", "op_delete"), ("operator()", "op_call"), ("operator[]", "op_index"),
       ("operator->*", "op_arrow_star"), ("operator->", "op_arrow"), ("operator<<=", "op_shl_assign"),
       ("operator>>=", "op_shr_assign"), ("operator<<", "op_shl"), ("operator>>", "op_shr"),
       ("operator==", "op_eq"), ("operator!=", "op_ne"), ("operator<=", "op_le"), ("operator>=", "op_ge"),
       ("operator&&", "op_land"), ("operator||", "op_lor"), ("operator++", "op_inc"), ("operator--", "op_dec"),
       ("operator+=", "op_add_assign"), ("operator-=", "op_sub_assign"), ("operator*=", "op_mul_assign"),
       ("operator/=", "op_div_assign"), ("operator%=", "op_mod_assign"), ("operator&=", "op_and_assign"),
       ("operator|=", "op_or_assign"), ("operator^=", "op_xor_assign"), ("operator<", "op_lt"),
       ("operator>", "op_gt"), ("operator=", "op_assign"), ("operator+", "op_add"), ("operator-", "op_sub"),
       ("operator*", "op_mul"), ("operator/", "op_div"), ("operator%", "op_mod"), ("operator&", "op_and"),
       ("operator|", "op_or"), ("operator^", "op_xor"), ("operator!", "op_not"), ("operator~", "op_compl"),
       ("operator,", "op_comma")]
SUB_RE = re.compile(r"\bsub_([0-9A-F]{8})\b")
INSN_RE = re.compile(r"/\* 0x([0-9A-F]{8}): (.*?) \*/")
FN_RE = re.compile(r"^void (sub_[0-9A-F]{8})\(void\) \{$", re.M)
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


# ------------------------------------------------------------------------------------------ names
def _split_scopes(name):
    """'a<b::c>::d' -> ['a<b::c>', 'd'] (only top-level '::' split; backtick quotes are atomic)."""
    out, cur, depth, q = [], "", 0, 0
    i = 0
    while i < len(name):
        c = name[i]
        if c == "`":
            q += 1
        elif c == "'" and q:
            q -= 1
        elif c == "<" and not q and not name.startswith("operator", max(0, i - 8)):
            depth += 1
        elif c == ">" and not q and depth:
            depth -= 1
        if name.startswith("::", i) and not depth and not q:
            out.append(cur)
            cur = ""
            i += 2
            continue
        cur += c
        i += 1
    out.append(cur)
    return out


def _sanitize_part(p):
    for op, rep in OPS:
        if p.startswith(op) and (len(p) == len(op) or p[len(op)] in "<"):
            p = rep + p[len(op):]
            break
    if p.startswith("operator "):          # conversion operator: 'operator float' -> op_cast_float
        p = "op_cast_" + p[len("operator "):]
    p = p.replace(" *", "_p").replace("*", "_p").replace("&", "_r").replace("::", "__")
    p = re.sub(r"[^A-Za-z0-9_]+", "_", p)
    return p.strip("_")


def cname_of(pdb_name):
    """PDB procedure name -> C identifier stem (deterministic, documented rules):
    '::' -> '__'; ctor 'X::X' -> 'X__ctor'; dtor 'X::~X' -> 'X__dtor'; operators -> op_*;
    '*' -> '_p', '&' -> '_r'; any other non-identifier run -> '_'; a leading digit gets 'f_'."""
    parts = _split_scopes(pdb_name)
    if len(parts) >= 2:
        last, cls = parts[-1], parts[-2]
        cls_base = cls.split("<")[0]
        if last == cls or last == cls_base or last.split("<")[0] == cls_base and not last.startswith("~"):
            parts[-1] = "ctor"
        elif last.startswith("~") and last[1:].split("<")[0] == cls_base:
            parts[-1] = "dtor"
    s = "__".join(x for x in (_sanitize_part(p) for p in parts) if x)
    if not s:
        s = "anon"
    if s[0].isdigit():
        s = "f_" + s
    return s


def assign_cnames(rows, reserved):
    """rows: [(va, pdb_name)] -> {va: (cname, rule)}. A stem used by more than one procedure, or equal
    to a reserved identifier, gets '_<VA8>' on every member (deterministic, independent of order)."""
    stems = {va: cname_of(n) for va, n in rows}
    count = collections.Counter(stems.values())
    out = {}
    for va, n in rows:
        s = stems[va]
        if count[s] > 1:
            out[va] = (f"{s}_{va:08X}", "overload_va")
        elif s in reserved or s.startswith("sub_") or s.startswith("L_"):
            out[va] = (f"{s}_{va:08X}", "reserved_va")
        else:
            out[va] = (s, "pdb_name")
    vals = collections.Counter(v[0] for v in out.values())
    dup = [k for k, c in vals.items() if c > 1]
    if dup:
        raise SystemExit(f"ANNOTATE_PDB REFUSED: {len(dup)} cname collisions after VA suffixing, e.g. {dup[:3]}")
    return out


# ------------------------------------------------------------------------------------------ undecorate
_DBGHELP = None


def undecorate(n, full=None):
    global _DBGHELP
    if not n.startswith("?"):
        return n
    if _DBGHELP is None:
        _DBGHELP = ctypes.windll.dbghelp
    buf = ctypes.create_string_buffer(8192)
    # vftables / RTTI: the full form keeps the `{for `Base'}` that tells a class's several vtables apart
    if full is None:
        full = n.startswith("??_7") or n.startswith("??_R")
    r = _DBGHELP.UnDecorateSymbolName(n.encode("utf-8", "replace"), buf, 8192, 0x0 if full else 0x1000)
    s = buf.value.decode("utf-8", "replace") if r else n
    return s[6:] if full and s.startswith("const ") else s


# ------------------------------------------------------------------------------------------ PDB facts
def _named_streams(msf):
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
            out[buf[k:buf.index(b"\0", k)].decode()] = v
    return out


def parse_methodlist(tpi, ti):
    """LF_METHODLIST (0x1206) -> [(attr, type, vbaseoff|None)] (rfgdt's Tpi keeps no entries for it)."""
    return tpi.mlists.get(ti, [])


def load_methodlists(pdb):
    data = pdb.msf.stream(2)
    ver, hsz, tb, te, nbytes = struct.unpack_from("<IIIII", data, 0)
    out = {}
    o, ti = hsz, tb
    while o < hsz + nbytes:
        ln, leaf = struct.unpack_from("<HH", data, o)
        if leaf == 0x1206:
            b = data[o + 4:o + 2 + ln]
            p, ents = 0, []
            while p + 8 <= len(b):
                attr, _pad, t = struct.unpack_from("<HHI", b, p)
                p += 8
                mprop = (attr >> 2) & 7
                vbo = None
                if mprop in (4, 6):
                    vbo = struct.unpack_from("<I", b, p)[0]
                    p += 4
                ents.append((attr, t, vbo))
            out[ti] = ents
        o += 2 + ln
        ti += 1
    return out


class Facts:
    """Every address-keyed record of rfg.pdb the pass uses. `shift` moves every record address (control)."""

    def __init__(self, pdb_path, shift=0):
        t0 = time.time()
        self.pdb = pdb = Pdb(pdb_path)
        self.tpi = pdb.tpi
        self.tpi.mlists = load_methodlists(pdb)
        sh = shift
        ns = _named_streams(pdb.msf)
        names = pdb.msf.stream(ns["/names"])

        def strtab(off):
            return names[12 + off:names.index(b"\0", 12 + off)].decode("utf-8", "replace")
        s3 = pdb.msf.stream(3)
        modi_sz = struct.unpack_from("<i", s3, 24)[0]
        mods, o = [], 64
        while o < 64 + modi_sz:
            sn, symb, c11, c13 = struct.unpack_from("<HIII", s3, o + 34)
            e1 = s3.index(b"\0", o + 64)
            e2 = s3.index(b"\0", e1 + 1)
            mods.append((sn, symb, c11, c13, s3[o + 64:e1].decode("utf-8", "replace")))
            o = (e2 + 1 + 3) & ~3
        self.procs = {}          # va -> dict
        self.lines = collections.defaultdict(list)   # va -> [(file, line)]
        self.callsites = {}
        self.labels = {}
        self.data = []           # (va, name, typ)
        self.n_line_records = 0
        for sn, symb, c11, c13, mname in mods:
            if sn == 0xFFFF:
                continue
            st = pdb.msf.stream(sn)
            cur = {"p": None, "end": -1, "blocks": []}

            def on(kind, b, o, end, cur=cur):
                rec = o - 4
                if cur["p"] is not None and rec >= cur["end"]:
                    cur["p"] = None
                while cur["blocks"] and rec >= cur["blocks"][-1][0]:
                    cur["blocks"].pop()
                p = cur["p"]
                if kind in PROC_KINDS:
                    pend = struct.unpack_from("<I", b, o + 4)[0]
                    plen = struct.unpack_from("<I", b, o + 12)[0]
                    typ = struct.unpack_from("<I", b, o + 24)[0]
                    off, seg = struct.unpack_from("<IH", b, o + 28)
                    va = pdb.va_of(seg, off)
                    nm = cstr(b, o + 35)[0]
                    p = dict(name=nm, typ=typ, size=plen, mod=mname, vars=[], frameproc=None, statics=[])
                    self.procs.setdefault(va + sh if va is not None else None, p)
                    cur["p"], cur["end"], cur["blocks"] = p, pend, []
                elif p is None:
                    if kind in (0x110D, 0x110C):
                        typ, off, seg = struct.unpack_from("<IIH", b, o)
                        va = pdb.va_of(seg, off)
                        if va is not None:
                            self.data.append((va + sh, cstr(b, o + 10)[0], typ))
                    return
                elif kind == 0x1103:   # S_BLOCK32
                    pend, ln, off, seg = struct.unpack_from("<IIIH", b, o + 4)
                    va = pdb.va_of(seg, off)
                    cur["blocks"].append((pend, (va + sh, va + sh + ln) if va is not None else None))
                elif kind == 0x110B:
                    off, typ = struct.unpack_from("<iI", b, o)
                    p["vars"].append(("bp", None, off, typ, cstr(b, o + 8)[0], self._scope(cur)))
                elif kind == 0x1111:
                    off, typ, reg = struct.unpack_from("<iIH", b, o)
                    p["vars"].append(("rr", reg, off, typ, cstr(b, o + 10)[0], self._scope(cur)))
                elif kind == 0x1106:
                    typ, reg = struct.unpack_from("<IH", b, o)
                    p["vars"].append(("reg", reg, 0, typ, cstr(b, o + 6)[0], self._scope(cur)))
                elif kind == 0x1012:
                    p["frameproc"] = struct.unpack_from("<IIIIIHI", b, o)
                elif kind in (0x110C, 0x110D):
                    typ, off, seg = struct.unpack_from("<IIH", b, o)
                    va = pdb.va_of(seg, off)
                    if va is not None:
                        nm = cstr(b, o + 10)[0]
                        p["statics"].append((va + sh, nm, typ))
                        self.data.append((va + sh, p["name"] + "::" + nm, typ))
                elif kind == 0x1105:
                    off, seg = struct.unpack_from("<IH", b, o)
                    va = pdb.va_of(seg, off)
                    nm = cstr(b, o + 7)[0]
                    if va is not None and not nm.startswith("$"):
                        self.labels[va + sh] = nm
                elif kind == 0x1139:
                    off, seg, _, typ = struct.unpack_from("<IHHI", b, o)
                    va = pdb.va_of(seg, off)
                    if va is not None:
                        self.callsites[va + sh] = typ
            walk_syms(st[:symb], 4, on)
            # C13 lines
            c = st[symb + c11:symb + c11 + c13]
            chk, subs, q = {}, [], 0
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
                if kind != 0xF2:
                    continue
                off, seg, flags, csz = struct.unpack_from("<IHHI", b, 0)
                base = pdb.va_of(seg, off)
                if base is None:
                    continue
                r = 12
                while r + 12 <= len(b):
                    fid, n, blen = struct.unpack_from("<III", b, r)
                    fname = chk.get(fid, "?")
                    for i in range(n):
                        lo, fl = struct.unpack_from("<II", b, r + 12 + 8 * i)
                        self.n_line_records += 1
                        ent = (fname, fl & 0xFFFFFF)
                        lst = self.lines[base + lo + sh]
                        if ent not in lst:
                            lst.append(ent)
                    r += blen
        # global symbol stream data + publics
        gs = pdb.msf.stream(pdb.symrec)
        self.publics = collections.defaultdict(list)

        def on_g(kind, b, o, end):
            if kind in (0x110D, 0x110C):
                typ, off, seg = struct.unpack_from("<IIH", b, o)
                va = pdb.va_of(seg, off)
                if va is not None:
                    self.data.append((va + sh, cstr(b, o + 10)[0], typ))
            elif kind == 0x110E:
                flags, off, seg = struct.unpack_from("<IIH", b, o)
                va = pdb.va_of(seg, off)
                if va is not None:
                    self.publics[va + sh].append(cstr(b, o + 10)[0])
        walk_syms(gs, 0, on_g)
        self.data = sorted(set(self.data))
        self.load_s = time.time() - t0

    @staticmethod
    def _scope(cur):
        for pend, rng in reversed(cur["blocks"]):
            if rng is not None:
                return rng
        return None


# ------------------------------------------------------------------------------------------ type helpers
def tname(tpi, ti, depth=0):
    """Readable C++ spelling of a type index for comments (resolves pointers/arrays/procs)."""
    if depth > 10:
        return "..."
    if ti < 0x1000:
        return tpi.name(ti)
    leaf, r = tpi.rec(ti)
    if leaf == 0x1001:
        return ("const " if r.get("const") else "") + ("volatile " if r.get("volatile") else "") + \
            tname(tpi, r["type"], depth + 1)
    if leaf == 0x1002:
        inner = tpi.rec(tpi.strip(r["type"]))[0] if r["type"] >= 0x1000 else None
        star = "&" if r["mode"] in (1, 4) else "*"
        if inner in (0x1008, 0x1009):
            return proto_str(tpi, tpi.strip(r["type"]), "(%s)" % star, depth=depth + 1)
        return tname(tpi, r["type"], depth + 1) + " " + star
    if leaf == 0x1503:
        es = tpi.sizeof(r["elem"])
        n = r["size"] // es if es else 0
        return "%s[%d]" % (tname(tpi, r["elem"], depth + 1), n)
    if leaf in (0x1008, 0x1009):
        return proto_str(tpi, ti, "", depth=depth + 1)
    if leaf == 0x1205:
        return "%s:%d" % (tname(tpi, r["type"], depth + 1), r["length"])
    return tpi.name(ti)


def proc_args(tpi, ti):
    leaf, r = tpi.rec(ti)
    if leaf not in (0x1008, 0x1009):
        return None
    al = tpi.rec(r["arglist"])
    return al[1].get("args", []) if al[0] == 0x1201 else None


def proto_str(tpi, ti, name, pnames=None, depth=0):
    leaf, r = tpi.rec(ti)
    if leaf not in (0x1008, 0x1009):
        return "?" + name
    args = proc_args(tpi, ti) or []
    parts = []
    for k, a in enumerate(args):
        if a == 0:
            parts.append("...")
            continue
        s = tname(tpi, a, depth + 1)
        if pnames and k < len(pnames) and pnames[k]:
            s += " " + pnames[k]
        parts.append(s)
    cc = CC_NAME.get(r["cc"], "cc%#x" % r["cc"])
    ret = tname(tpi, r["rv"], depth + 1)
    return "%s %s %s(%s)" % (ret, cc, name, ", ".join(parts) or "void")


def stack_pop_of_type(tpi, ti):
    """Bytes a callee of this type pops (x86 MSVC); None when the type alone does not decide it."""
    ti = tpi.strip(ti)
    leaf, r = tpi.rec(ti) if ti >= 0x1000 else (None, {})
    if leaf == 0x1002:
        ti = tpi.strip(r["type"])
        leaf, r = tpi.rec(ti) if ti >= 0x1000 else (None, {})
    if leaf not in (0x1008, 0x1009):
        return None
    args = proc_args(tpi, ti)
    if args is None:
        return None
    if args and args[-1] == 0:     # varargs: caller cleans
        return 0
    if r["cc"] == 0x00:
        return 0
    if r["cc"] not in (0x07, 0x0B, 0x04):
        return None
    sizes = []
    for a in args:
        s = tpi.sizeof(a)
        if not s:
            return None
        sizes.append(s)
    if r["cc"] == 0x04:    # fastcall: first two integral/pointer args of <= 4 bytes in ecx, edx
        regs, rest = 0, []
        for a, s in zip(args, sizes):
            if regs < 2 and s <= 4 and not tpi.is_float(a) and not tpi.is_udt(a):
                regs += 1
            else:
                rest.append(s)
        sizes = rest
    total = sum((s + 3) & ~3 for s in sizes)
    if tpi.is_udt(r["rv"]):
        if leaf == 0x1009:
            total += 4     # member functions return every UDT through a hidden pointer
        else:
            return None    # free function: register vs hidden pointer depends on POD-ness
    return total


# ------------------------------------------------------------------------------------------ vtables
class VTables:
    """Virtual slot -> method from TPI field lists (LF_ONEMETHOD / LF_METHODLIST vbaseoff)."""

    def __init__(self, tpi):
        self.tpi = tpi
        self.memo = {}

    def methods(self, cls):
        """[(name, type, mprop, vbaseoff)] of a class's own methods."""
        out = []
        for f in self.tpi.fields(cls):
            if f["k"] == "onemethod":
                out.append((f["name"], f["type"], f["mprop"], f["vbaseoff"]))
            elif f["k"] == "method":
                for attr, t, vbo in self.tpi.mlists.get(f["mlist"], []):
                    out.append((f["name"], t, (attr >> 2) & 7, vbo))
        return out

    def key(self, t):
        """Structural identity of an LF_MFUNCTION record (the TPI holds identical records under several
        indices): class (forward refs resolved), return, this, convention, arguments, this-adjust."""
        leaf, r = self.tpi.rec(t)
        if leaf != 0x1009:
            return ("ti", t)
        args = tuple(self.tpi.rec(r["arglist"])[1].get("args", ()))
        return (self.tpi.resolve(r["cls"]), r["rv"], r["this"], r["cc"], args, r["thisadjust"])

    def primary_base(self, cls):
        for f in self.tpi.fields(cls):
            if f["k"] == "base" and f["offset"] == 0:
                return self.tpi.resolve(f["type"])
        return None

    def sig(self, t):
        """Signature of a method type without its class: return, convention, arguments (TPI holds
        identical records under several indices, and an override's type names the overriding class)."""
        leaf, r = self.tpi.rec(t)
        if leaf != 0x1009:
            return ("ti", t)
        return (r["rv"], r["cc"], tuple(self.tpi.rec(r["arglist"])[1].get("args", ())))

    def slot_map(self, cls, depth=0):
        """Primary vtable of `cls`: {slot offset: (method name, declaring class name, signature)} built from
        the primary-base chain's intro virtuals (LF_ONEMETHOD/LF_METHODLIST vbaseoff), then this class's
        own intro virtuals; an override (mprop 1) re-owns the slot whose name AND signature it matches."""
        cls = self.tpi.resolve(cls)
        if cls in self.memo:
            return self.memo[cls]
        self.memo[cls] = {}
        b = self.primary_base(cls)
        m = dict(self.slot_map(b, depth + 1)) if b and depth < 64 else {}
        cname = self.tpi.rec(cls)[1].get("name", "?")
        for name, t, mprop, vbo in self.methods(cls):
            if mprop in (4, 6) and vbo is not None:
                m[vbo] = (name, cname, self.sig(t))
            elif mprop == 1:
                hits = [o for o, (n, c, s) in m.items() if n == name and s == self.sig(t)]
                if len(hits) == 1:
                    m[hits[0]] = (name, cname, self.sig(t))
        self.memo[cls] = m
        return m

    def slot_of_method(self, cls, mtype, slot):
        """(name, owner) when the method at `slot` of `cls`'s primary vtable has `mtype`'s signature."""
        e = self.slot_map(cls).get(slot)
        if e is None:
            return None, "no_slot"
        if e[2] != self.sig(mtype):
            return None, "sig_mismatch"
        return (e[0], e[1]), None


# ------------------------------------------------------------------------------------------ the pass
def mem_operands(op):
    return re.findall(r"(?:(byte|word|dword|qword|xmmword|tbyte|fword) ptr )?(?:([cdefgs]s):)?\[([^\]]+)\]", op)


def parse_addr(expr):
    """'esp + eax*4 + 0x10' -> (base, index, scale, disp)."""
    base = index = None
    scale, disp = 1, 0
    for sign, term in re.findall(r"([+-]?)\s*([^+-]+)", expr.replace(" ", "")):
        neg = sign == "-"
        if "*" in term:
            index, sc = term.split("*")
            scale = int(sc)
        elif re.fullmatch(r"0x[0-9a-f]+|\d+", term):
            v = int(term, 0)
            disp += -v if neg else v
        else:
            if base is None:
                base = term
            else:
                index = term
    return base, index, scale, disp & 0xFFFFFFFF if disp >= 0 else disp


class Annotator:
    def __init__(self, root, shift=0, cnames_path=None):
        self.root = root
        self.f = Facts(os.path.join(root, "input", "rfg.pdb"), shift=shift)
        tpi = self.tpi = self.f.tpi
        self.vt = VTables(tpi)
        self.exe = open(os.path.join(root, "input", "rfg.exe"), "rb").read()
        d = self.exe
        lf = struct.unpack_from("<I", d, 0x3C)[0]
        nsec, optsz = struct.unpack_from("<HH", d, lf + 6)[0], struct.unpack_from("<H", d, lf + 20)[0]
        self.base = struct.unpack_from("<I", d, lf + 24 + 28)[0]
        self.secs = []
        for i in range(nsec):
            nm, vsz, va, rsz, rp = struct.unpack_from("<8sIIII", d, lf + 24 + optsz + 40 * i)
            self.secs.append((self.base + va, vsz, rp, rsz))
        self.img_lo = self.base
        self.img_hi = max(a + v for a, v, _, _ in self.secs)
        # data symbols: sorted starts with (end, names, typ)
        by = collections.defaultdict(lambda: [0, set(), set()])
        for va, nm, typ in self.f.data:
            e = by[va]
            sz = tpi.sizeof(typ)
            e[0] = max(e[0], sz)
            e[1].add(nm)
            e[2].add(typ)
        self.dstarts = sorted(by)
        self.dinfo = by
        self.dpmax, m = [], 0
        for s in self.dstarts:
            m = max(m, s + max(by[s][0], 1))
            self.dpmax.append(m)
        self.pubs = {va: sorted(set(undecorate(n) for n in ns)) for va, ns in self.f.publics.items()}
        self.imports = {}
        for va, ns in self.f.publics.items():
            for n in ns:
                if n.startswith("__imp_"):
                    self.imports[va] = n
        self.cnames = {}
        if cnames_path and os.path.exists(cnames_path):
            with open(cnames_path, encoding="utf-8") as fh:
                fh.readline()
                for line in fh:
                    va, sub, cn, rule, pdbn = line.rstrip("\n").split("\t")
                    self.cnames[sub] = cn
        self.sub2va = {}
        self.stats = collections.Counter()
        self.ex = collections.defaultdict(list)    # category -> a few (function, insn, text) examples
        self.pops = None

    # -- image --
    def read(self, va, n):
        for sva, vsz, rp, rsz in self.secs:
            if sva <= va < sva + vsz:
                o = va - sva
                b = self.exe[rp + o: rp + min(o + n, rsz)] if o < rsz else b""
                return b + b"\0" * (n - len(b))
        return None

    # -- address -> symbol --
    def sym_at(self, v, procs_by_va):
        """Image address -> symbol text. Order: procedure start, PDB label, data symbol starting at v,
        public at v, data symbol containing v (within sizeof its type)."""
        if not (self.img_lo <= v < self.img_hi):
            return None
        if v in procs_by_va:
            return procs_by_va[v]
        if v in self.f.labels:
            return "label " + self.f.labels[v]
        if v in self.dinfo:
            return self._dsym(v, v)
        if v in self.pubs:
            return "|".join(self.pubs[v])
        i = bisect.bisect_right(self.dstarts, v) - 1
        while i >= 0 and self.dpmax[i] > v:
            s = self.dstarts[i]
            if s + max(self.dinfo[s][0], 1) > v:
                return self._dsym(s, v)
            i -= 1
        return None

    def _dsym(self, s, v):
        size, nms, typs = self.dinfo[s]
        ty = tname(self.tpi, sorted(typs)[0]) if len(typs) == 1 else "?"
        return "|".join(sorted(nms)) + (f"+{v - s:#x}" if v != s else "") + f" ({ty})"

    # -- callee pops measured from the lifted bodies --
    def measure_pops(self, bodies):
        """bodies: {va: [(insn_va, text)]} -> {va: pop or None}; from `ret N`, following tail jumps."""
        rets, tails = {}, {}
        for va, ins in bodies.items():
            rs, ts = set(), set()
            for a, t in ins:
                if t == "ret" or t.startswith("ret "):
                    rs.add(int(t[4:], 0) if t != "ret" else 0)
                m = re.fullmatch(r"jmp 0x([0-9a-f]+)", t)
                if m:
                    tgt = int(m.group(1), 16)
                    if tgt in bodies and tgt != va and not any(a2 == tgt for a2, _ in ins[:1]):
                        if tgt not in {a2 for a2, _ in ins}:
                            ts.add(tgt)
                m = re.fullmatch(r"jmp dword ptr \[0x([0-9a-f]+)\]", t)
                if m and len(ins) == 1:
                    imp = self.imports.get(int(m.group(1), 16))
                    if imp and imp.startswith("__imp__"):      # C decoration: _name (cdecl) / _name@N
                        mm = re.search(r"@(\d+)$", imp)
                        rs.add(int(mm.group(1)) if mm else 0)
            if not ins:     # an import thunk lifts as a bare tail jump with no asm comment: decode it
                raw = self.read(va, 16)
                dec = next(_MD.disasm_lite(raw, va, 1), None) if raw else None
                if dec and dec[2] == "jmp":
                    m = re.fullmatch(r"dword ptr \[0x([0-9a-f]+)\]", dec[3])
                    imp = self.imports.get(int(m.group(1), 16)) if m else None
                    if imp and imp.startswith("__imp__"):
                        mm = re.search(r"@(\d+)$", imp)
                        rs.add(int(mm.group(1)) if mm else 0)
            rets[va], tails[va] = rs, ts
        memo = {}

        def pop(va, stack=()):
            if va in memo:
                return memo[va]
            if va in stack:
                return "cycle"
            vals = set(rets.get(va, ()))
            for t in tails.get(va, ()):
                p = pop(t, stack + (va,))
                if p is None:
                    memo[va] = None
                    return None
                if p != "cycle":
                    vals.add(p)
            r = vals.pop() if len(vals) == 1 else None
            memo[va] = r
            return r
        self.pops = {va: pop(va) for va in bodies}
        for va in list(self.pops):
            if self.pops[va] == "cycle":
                self.pops[va] = None
        return self.pops

    # -- per-function analysis --
    def analyze(self, fva, ins, case_targets, noreturn):
        """ins: [(va, asm)] sorted. Returns per-instruction annotation lists and header lines."""
        tpi = self.tpi
        self._cur_fva = fva
        st = self.stats
        p = self.f.procs.get(fva)
        idx = {a: k for k, (a, _) in enumerate(ins)}
        sizes = {}
        for k, (a, t) in enumerate(ins):
            raw = self.read(a, 16)
            dec = next(_MD.disasm_lite(raw, a, 1), None)
            if dec is None or (dec[2] + (" " + dec[3] if dec[3] else "")).strip() != t.strip():
                st["insn_decode_mismatch"] += 1
                self._ex("insn_decode_mismatch", fva, a, t)
                return None
            sizes[a] = dec[1]
        # every non-terminating instruction must fall through to another instruction of the body
        for a, t in ins:
            mn = t.partition(" ")[0]
            if mn not in ("ret", "retn", "jmp", "int3", "ud2", "hlt", "call") and a + sizes[a] not in idx:
                st["insn_fallthrough_missing"] += 1
                self._ex("fallthrough_missing", fva, a, t)
        notes = collections.defaultdict(list)
        pre = collections.defaultdict(list)
        # ---- lines
        own_file = None
        if p is not None:
            fl = self.f.lines.get(fva)
            own_file = fl[0][0] if fl else None
        for a, _ in ins:
            for fname, ln in self.f.lines.get(a, ()):
                pre[a].append(("line", fname, ln))
        # ---- labels
        for a, _ in ins:
            if a in self.f.labels and a != fva:
                pre[a].append(("label", self.f.labels[a]))
        # ---- frame model
        kind = "fpo"
        if len(ins) >= 2 and ins[0][1] == "push ebp" and ins[1][1] == "mov ebp, esp":
            kind = "ebp"
        seh = any(re.fullmatch(r"call 0x([0-9a-f]+)", t) and int(t[7:], 16) in self.seh_prologs for _, t in ins[:8])
        if seh:
            kind = "seh"
        if any(t.startswith("and esp, ") for _, t in ins):
            kind = "aligned" if kind == "ebp" else "fpo_and"
        states, conflict = self.track(fva, ins, idx, sizes, case_targets, noreturn)
        frame_vars, refused = [], collections.Counter()
        if p is not None:
            for vk, reg, off, typ, nm, scope in p["vars"]:
                if vk == "reg":
                    continue
                if vk == "bp":
                    if kind == "fpo":
                        loc = ("E", off)
                    elif kind in ("ebp", "seh"):
                        loc = ("E", off - 4)
                    elif kind == "aligned":
                        loc = ("A", off)
                    else:
                        refused["bprel_" + kind] += 1
                        continue
                elif reg == 22 and kind in ("ebp", "seh", "aligned"):
                    loc = ("E", off - 4)
                elif reg == 21 and kind == "fpo":
                    loc = ("E", off)
                elif reg == 21 and kind == "aligned":
                    loc = ("A", off)
                else:
                    refused["regrel_r%d_%s" % (reg, kind)] += 1
                    continue
                frame_vars.append((loc, max(tpi.sizeof(typ), 1), nm, typ, scope))
        for k, v in refused.items():
            st["frame_record_refused_" + k] += v
        st["frame_records_placed"] += len(frame_vars)
        if conflict:
            st["fn_frame_conflict"] += 1
        # ---- operands
        procs_by_va = self.procs_by_va
        for a, t in ins:
            mn, _, op = t.partition(" ")
            s = states.get(a) if not conflict else None
            # stack operands
            for width, seg, expr in mem_operands(op):
                base, index, scale, disp = parse_addr(expr)
                if seg:
                    continue
                if base == "ebp" and kind in ("fpo", "fpo_and"):
                    st["ebp_general_register_operands"] += 1
                    continue
                if base in ("esp", "ebp") and s is not None:
                    st["stack_operands"] += 1
                    reg = s[0] if base == "esp" else s[1]
                    if reg is None:
                        st["stack_operands_unknown_base"] += 1
                        self._ex("unknown_base", fva, a, t)
                        continue
                    sd = disp if disp < 0x80000000 else disp - 0x100000000
                    if mn == "pop" and base == "esp":
                        sd += 4          # pop computes its esp-based destination after the increment
                    addr = (reg[0], reg[1] + sd)
                    hits = [v for v in frame_vars if v[0][0] == addr[0] and v[0][1] <= addr[1] < v[0][1] + v[1]
                            and (v[4] is None or v[4][0] <= a < v[4][1])]
                    if len({(h[0], h[2]) for h in hits}) > 1:
                        starts = {h[0] for h in hits}
                        if len(starts) != 1:
                            st["stack_operands_ambiguous"] += 1
                            self._ex("ambiguous", fva, a, t + " | " + str([(h[0], h[2]) for h in hits]))
                            continue
                        k = addr[1] - hits[0][0][1]
                        nm = ("&" if mn == "lea" else "") + "{" + "|".join(sorted({h[2] for h in hits})) + "}" + \
                            (f"+{k:#x}" if k else "")
                        notes[a].append(f"[{expr}]={nm}")
                        st["stack_operands_named_shared_slot"] += 1
                        continue
                    if not hits:
                        st["stack_operands_unnamed"] += 1
                        self._ex("unnamed", fva, a, f"{t} | {addr}")
                        continue
                    v = hits[0]
                    k = addr[1] - v[0][1]
                    nm = ("&" if mn == "lea" else "") + v[2] + (f"+{k:#x}" if k else "") + \
                        (f"[{index}*{scale}]" if index else "")
                    notes[a].append(f"[{expr}]={nm}")
                    st["stack_operands_named"] += 1
                elif base in ("esp", "ebp"):
                    st["stack_operands"] += 1
                    st["stack_operands_conflict_fn" if conflict else "stack_operands_unknown_base"] += 1
            # image addresses (displacements and immediates)
            is_branch = mn.startswith("j") or mn.startswith("loop") or mn == "call"
            for hx in re.findall(r"0x[0-9a-f]+", op):
                v = int(hx, 16)
                if not (self.img_lo <= v < self.img_hi):
                    continue
                if is_branch and re.fullmatch(r"0x[0-9a-f]+", op):
                    st["image_addr_branch_targets"] += 1      # already a callee cname / goto label in code
                    continue
                st["image_addr_operands"] += 1
                sym = self.sym_at(v, procs_by_va)
                if sym is None:
                    st["image_addr_unresolved"] += 1
                    self._ex("addr_unresolved", fva, a, t)
                    continue
                notes[a].append(f"{hx}={sym}")
                st["image_addr_named"] += 1
            # indirect calls
            if mn == "call" and not re.fullmatch(r"0x[0-9a-f]+", op):
                st["icalls"] += 1
                typ = self.f.callsites.get(a)
                m = re.fullmatch(r"dword ptr \[0x([0-9a-f]+)\]", op)
                if m and int(m.group(1), 16) in self.imports:
                    notes[a].append("import " + self.imports[int(m.group(1), 16)].replace("__imp_", "", 1))
                    st["icalls_import"] += 1
                    continue
                if typ is None:
                    st["icalls_no_callsite"] += 1
                    continue
                vc = self.vcall(ins, idx, a, op, typ, case_targets)
                if vc:
                    notes[a].append(vc)
                    st["icalls_virtual_named"] += 1
                else:
                    notes[a].append("icall " + proto_str(tpi, tpi.strip(typ) if tpi.rec(tpi.strip(typ))[0] != 0x1002
                                                         else tpi.strip(tpi.rec(tpi.strip(typ))[1]["type"]), "")
                                    .replace("  (", " (") + f" [ti {typ:#x}]")
                    st["icalls_typed"] += 1
        # ---- header
        hdr = []
        if p is not None:
            pr = p["typ"]
            params = sorted((v for v in frame_vars if v[0][0] == "E" and v[0][1] >= 4), key=lambda v: v[0][1])
            leaf = tpi.rec(pr)[0] if pr >= 0x1000 else None
            pn = [v[2] for v in params]
            if leaf in (0x1008, 0x1009):
                hdr.append("PDB " + proto_str(tpi, pr, p["name"], pnames=pn if len(pn) == len(proc_args(tpi, pr) or [])
                                              else None))
                if leaf == 0x1009:
                    hdr[-1] += "  [this: %s]" % tname(tpi, tpi.rec(pr)[1]["this"])
            else:
                hdr.append("PDB " + p["name"])
            fr = p["frameproc"]
            fdesc = f"frame {kind}" + (f", {fr[0]:#x} bytes locals, {fr[3]:#x} saved regs" if fr else "")
            if conflict:
                fdesc += ", stack NOT proven (frame names withheld)"
            hdr.append(fdesc)
            for v in sorted(frame_vars, key=lambda v: (v[0][0], v[0][1])):
                where = ("entry esp" if v[0][0] == "E" else "aligned esp") + (f"{v[0][1]:+#x}" if v[0][1] else "")
                role = "param" if v[0][0] == "E" and v[0][1] >= 4 else "local"
                hdr.append(f"{role} {tname(tpi, v[3])} {v[2]} @ {where}")
            for vk, reg, off, typ, nm, scope in p["vars"]:
                if vk == "reg":
                    hdr.append(f"register {tname(tpi, typ)} {nm} @ {CV_REG.get(reg, 'r%d' % reg)}")
            for va, nm, typ in p["statics"]:
                hdr.append(f"static {tname(tpi, typ)} {nm} @ {va:#010x}")
        return dict(notes=notes, pre=pre, hdr=hdr, own_file=own_file, conflict=conflict)

    def _ex(self, cat, fva, a, text):
        if len(self.ex[cat]) < 12 and (hash((fva, a)) % 97 == 0 or len(self.ex[cat]) < 3):
            self.ex[cat].append((f"{fva:#x}", f"{a:#x}", text))

    def vcall(self, ins, idx, a, op, typ, case_targets):
        """`call reg` <- `mov reg, [vp + N]` <- `mov vp, [obj (+k)]` in the same block -> named slot."""
        tpi = self.tpi
        fva = self._cur_fva

        def miss(why):
            self.stats["vcall_miss_" + why] += 1
            ctx = " ; ".join(x[1] for x in ins[max(0, idx[a] - 3):idx[a] + 1])
            self._ex("vcall_miss_" + why, fva, a, ctx)
            return None
        t = tpi.strip(typ)
        leaf, r = tpi.rec(t) if t >= 0x1000 else (None, {})
        if leaf != 0x1009:
            return None                      # not a member-function call type: no class to look in
        m = re.fullmatch(r"(e[a-ds][xip])", op)
        k = idx[a]
        if m:
            reg = m.group(1)
            j = self.def_in_block(ins, k, reg, case_targets)
            if j is None:
                return miss("reg_def_not_in_block")
            mm = re.fullmatch(r"mov %s, dword ptr \[(e[a-ds][xip])(?: \+ (0x[0-9a-f]+|\d+))?\]" % reg, ins[j][1])
            if not mm:
                return miss("reg_not_loaded_from_vptr_slot")
            vp, slot = mm.group(1), int(mm.group(2), 0) if mm.group(2) else 0
            jj = j
        else:
            mm = re.fullmatch(r"dword ptr \[(e[a-ds][xip])(?: \+ (0x[0-9a-f]+|\d+))?\]", op)
            if not mm:
                return miss("mem_form")
            vp, slot = mm.group(1), int(mm.group(2), 0) if mm.group(2) else 0
            jj = k
        j2 = self.def_in_block(ins, jj, vp, case_targets)
        if j2 is None:
            return miss("vptr_def_not_found")
        cls = tpi.resolve(r["cls"])
        m2 = re.fullmatch(r"mov %s, dword ptr \[e[a-ds][xip](?: \+ (0x[0-9a-f]+|\d+))?\]" % vp, ins[j2][1])
        m3 = re.fullmatch(r"mov %s, dword ptr \[0x([0-9a-f]+)\]" % vp, ins[j2][1])
        if m3:
            # vptr read straight out of a global object: the PDB must type that global as the class itself
            g = int(m3.group(1), 16)
            info = self.dinfo.get(g)
            if not info or len(info[2]) != 1 or tpi.resolve(tpi.strip(next(iter(info[2])))) != cls:
                return miss("vptr_global_not_of_call_class")
        elif not m2:
            return miss("vptr_not_a_load")
        elif m2.group(1):
            return miss("vptr_at_nonzero_offset")      # a secondary vtable: slot map of a base subobject
        hit, why = self.vt.slot_of_method(cls, t, slot)
        if hit is None:
            return miss(why)
        name, owner = hit
        cn = tpi.rec(cls)[1].get("name", "?")
        tgt = ""
        vt = self.vtable_va.get(cn)
        if vt is not None:
            raw = self.read(vt + slot, 4)
            fv = struct.unpack("<I", raw)[0] if raw else None
            if fv in self.procs_by_va:
                tgt = " -> " + self.procs_by_va[fv]
                # cross-check (second source): the image's vtable entry is a procedure named ...::<name>
                pn = self.pdb_name_of.get(fv, "")
                last = _split_scopes(pn)[-1] if pn else ""
                if last == name:
                    self.stats["vcall_vtable_entry_name_agrees"] += 1
                elif pn == "_purecall":
                    self.stats["vcall_vtable_entry_purecall"] += 1     # abstract in the static class
                    tgt = " -> _purecall (pure virtual in " + cn + ")"
                elif name.startswith("~") and "deleting destructor'" in last:
                    self.stats["vcall_vtable_entry_deleting_dtor"] += 1
                else:
                    self.stats["vcall_vtable_entry_name_differs"] += 1
                    self._ex("vcall_vtable_entry_name_differs", fva, a, f"{cn}::{name} vs {pn}")
        return f"vcall {cn}::{name} [slot {slot:#x}]{tgt} [ti {typ:#x}]"

    IMPLICIT_WRITERS = {"cdq", "cwde", "cbw", "cwd", "mul", "div", "idiv", "lodsb", "lodsw", "lodsd", "stosb",
                        "stosw", "stosd", "movsb", "movsw", "movsd", "cmpxchg", "rdtsc", "cpuid", "xadd", "xchg",
                        "rep", "repe", "repne", "lahf", "pop", "popal", "popad", "aaa", "aas", "daa", "das",
                        "scasb", "scasd", "cmpsb", "cmpsd", "loop", "in", "salc", "xlatb", "sahf"}
    ALIASES = {"eax": ("eax", "ax", "al", "ah"), "ebx": ("ebx", "bx", "bl", "bh"), "ecx": ("ecx", "cx", "cl", "ch"),
               "edx": ("edx", "dx", "dl", "dh"), "esi": ("esi", "si"), "edi": ("edi", "di"), "ebp": ("ebp", "bp"),
               "esp": ("esp", "sp")}

    def def_in_block(self, ins, k, reg, case_targets):
        """Index of the unique reaching definition of `reg` at ins[k], found by walking back through
        UNIQUE CFG predecessors only (a join point stops the search), crossing jumps (which write no
        register) but never a call, ret or implicit-register instruction. The definition must write the
        whole register through its first operand (a partial write stops the search)."""
        al = self.ALIASES[reg]
        idx = {a: i for i, (a, _) in enumerate(ins)}
        cur = ins[k][0]
        for _ in range(256):
            pr = self._preds.get(cur, ())
            if len(pr) != 1:
                return None
            cur = pr[0]
            j = idx[cur]
            mn, _, op = ins[j][1].partition(" ")
            if mn.startswith("j"):
                continue
            if mn in ("ret", "call") or mn in self.IMPLICIT_WRITERS:
                return None
            first = op.split(",")[0].strip()
            if first in al and mn not in ("cmp", "test", "push", "bt"):
                return j if first == reg else None
        return None

    def track(self, fva, ins, idx, sizes, case_targets, noreturn):
        """Forward esp/ebp dataflow. state = (esp, ebp), each None or (origin, delta)."""
        tpi = self.tpi
        n = len(ins)
        states = {}
        succ_map = {}
        self._preds = {}
        conflict = False
        if not ins or ins[0][0] != fva:
            return states, True
        states[fva] = (("E", 0), None)
        work = [fva]
        last_eax_imm = {}
        body = set(idx)
        while work:
            a = work.pop()
            esp, ebp = states[a]
            t = ins[idx[a]][1]
            mn, _, op = t.partition(" ")
            ops = [x.strip() for x in op.split(",")] if op else []
            nesp, nebp = esp, ebp
            nxt = a + sizes[a]
            succ = [nxt] if nxt in body else []

            def add(x, d):
                return None if x is None else (x[0], x[1] + d)
            if mn == "push":
                nesp = add(esp, -2 if op.startswith("word") else -4)
            elif mn == "pop":
                nesp = add(esp, 4)
                if ops and ops[0] == "ebp":
                    nebp = None
                if ops and ops[0] == "esp":
                    nesp = None
            elif mn in ("pushal", "pushad"):
                nesp = add(esp, -32)
            elif mn in ("popal", "popad"):
                nesp = add(esp, 32)
                nebp = None
            elif mn in ("pushfd", "pushf"):
                nesp = add(esp, -4)
            elif mn in ("popfd", "popf"):
                nesp = add(esp, 4)
            elif mn in ("sub", "add") and ops and ops[0] == "esp":
                if re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", ops[1]):
                    v = int(ops[1], 0)
                    nesp = add(esp, -v if mn == "sub" else v)
                else:
                    nesp = None
            elif mn == "and" and ops and ops[0] == "esp":
                nesp = ("A", 0) if esp is not None and esp[0] == "E" else None
            elif mn == "mov" and len(ops) == 2 and ops[0] == "ebp" and ops[1] == "esp":
                nebp = esp
            elif mn == "mov" and len(ops) == 2 and ops[0] == "esp" and ops[1] == "ebp":
                nesp = ebp
            elif mn == "lea" and ops and ops[0] in ("esp", "ebp"):
                b, ix, sc, d = parse_addr(ops[1].strip("[]"))
                d = d if d < 0x80000000 else d - 0x100000000
                src = esp if b == "esp" else ebp if b == "ebp" else None
                val = None if ix or src is None else add(src, d)
                if ops[0] == "esp":
                    nesp = val
                else:
                    nebp = val
            elif mn == "leave":
                nesp = add(ebp, 4)
                nebp = None
            elif mn == "mov" and len(ops) == 2 and ops[0] == "eax" and re.fullmatch(r"0x[0-9a-f]+|\d+", ops[1]):
                last_eax_imm[a] = int(ops[1], 0)
            elif mn == "call":
                mt = re.fullmatch(r"0x([0-9a-f]+)", op)
                if mt:
                    tgt = int(mt.group(1), 16)
                    if tgt in self.chkstk:
                        prev = [x for x in last_eax_imm if x < a]
                        imm = last_eax_imm[max(prev)] if prev else None
                        nesp = None if imm is None else add(esp, -imm)
                    elif tgt in self.seh_prologs:
                        nebp = add(esp, 4)
                        nesp = None
                    elif tgt in self.alloca:
                        nesp = None
                    else:
                        pp = self.pops.get(tgt)
                        if pp is None and tgt in self.f.procs:
                            pp = stack_pop_of_type(tpi, self.f.procs[tgt]["typ"])
                        nesp = None if pp is None else add(esp, pp)
                    if tgt in noreturn:
                        succ = []
                else:
                    pp = None
                    mi = re.fullmatch(r"dword ptr \[0x([0-9a-f]+)\]", op)
                    if mi and int(mi.group(1), 16) in self.imports:
                        nm = self.imports[int(mi.group(1), 16)]
                        mm = re.search(r"@(\d+)$", nm)
                        pp = int(mm.group(1)) if mm else (0 if nm.startswith("__imp__") else None)
                    elif a in self.f.callsites:
                        pp = stack_pop_of_type(tpi, self.f.callsites[a])
                    nesp = None if pp is None else add(esp, pp)
            elif mn in ("ret", "retn"):
                if esp is not None and esp != ("E", 0):
                    conflict = True
                succ = []
            elif mn == "jmp":
                mt = re.fullmatch(r"0x([0-9a-f]+)", op)
                if mt:
                    tgt = int(mt.group(1), 16)
                    if tgt in body:
                        succ = [tgt]
                    else:
                        if esp is not None and esp != ("E", 0):
                            conflict = True
                        succ = []
                elif "*4" in op.replace(" ", ""):
                    succ = [c for c in case_targets if c in body]
                else:
                    if esp is not None and esp != ("E", 0):
                        conflict = True
                    succ = []
            elif mn.startswith("j") or mn.startswith("loop"):
                mt = re.fullmatch(r"0x([0-9a-f]+)", op)
                if mt and int(mt.group(1), 16) in body:
                    succ.append(int(mt.group(1), 16))
            elif mn in ("int3", "ud2", "hlt"):
                succ = []
            elif ops and ops[0] in ("esp", "sp") and mn not in ("cmp", "test"):
                nesp = None
            elif ops and ops[0] in ("ebp", "bp") and mn not in ("cmp", "test"):
                nebp = None
            if mn == "xchg" and ("esp" in ops or "ebp" in ops):
                nesp, nebp = (None if "esp" in ops else nesp), (None if "ebp" in ops else nebp)
            new = (nesp, nebp)
            succ_map[a] = list(succ)
            if esp is not None and nesp is None and succ:
                why = "call_" + ("direct" if re.fullmatch(r"0x[0-9a-f]+", op) else "indirect") if mn == "call" else mn
                self.stats["esp_lost_at_" + why] += 1
                self._ex("esp_lost_" + why, fva, a, t)
            for s in succ:
                if s not in states:
                    states[s] = new
                    work.append(s)
                else:
                    old = states[s]
                    merged = []
                    for o_, n_ in zip(old, new):
                        if o_ == n_:
                            merged.append(o_)
                        elif o_ is not None and n_ is not None:
                            conflict = True
                            merged.append(None)
                        else:
                            merged.append(None)
                    merged = tuple(merged)
                    if merged != old:
                        states[s] = merged
                        work.append(s)
        preds = collections.defaultdict(list)
        for a, ss in succ_map.items():
            for s in ss:
                if a not in preds[s]:
                    preds[s].append(a)
        self._preds = preds
        return states, conflict


try:
    import capstone as _cs
    _MD = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_32)
except ImportError:  # pragma: no cover
    _MD = None


# ------------------------------------------------------------------------------------------ bodies
def split_bodies(text):
    ms = list(FN_RE.finditer(text))
    out = {}
    for i, m in enumerate(ms):
        end = ms[i + 1].start() if i + 1 < len(ms) else len(text)
        out[m.group(1)] = text[m.start():end]
    return out


LABEL_RE = re.compile(r"^L_([0-9A-F]{8}):", re.M)


def body_insns(body):
    """Instruction starts of a lifted body: every `/* 0xVA: asm */` comment plus every `L_VA:` label (the
    lifter writes some statements, e.g. `jmp [table]` through _ljump, with a label but no asm comment).
    -> [(va, asm text or None when only labelled)] sorted by VA."""
    out = {int(a, 16): t.strip() for a, t in INSN_RE.findall(body)}
    for a in LABEL_RE.findall(body):
        out.setdefault(int(a, 16), None)
    return sorted(out.items())


CASE_RE = re.compile(r"case 0x([0-9A-F]{8})u: goto L_")


class Pass:
    """Whole-program driver: computes the annotation of every body once."""

    def __init__(self, root, shift=0):
        self.root = root
        self.gen = os.path.join(root, "gen")
        self.cn_path = os.path.join(root, "config", "pdb_annot", "cnames.tsv")
        self.A = Annotator(root, shift=shift, cnames_path=self.cn_path)
        A = self.A
        nm = {}
        with open(os.path.join(root, "config", "names.tsv"), encoding="utf-8") as fh:
            fh.readline()
            for line in fh:
                va, cn, pdbn = line.rstrip("\n").split("\t")[:3]
                nm[int(va, 16)] = (cn, pdbn)
        self.names = nm
        spec = {}
        for va, (cn, pdbn) in nm.items():
            spec.setdefault(pdbn, set()).add(va)
        A.chkstk = spec.get("_chkstk", set())
        A.alloca = spec.get("_alloca_probe_16", set()) | spec.get("__alloca_probe_8", set())
        A.seh_prologs = set().union(*(spec.get(k, set()) for k in ("__SEH_prolog4", "__SEH_prolog4_GS")))
        self.noreturn = set()
        with open(os.path.join(self.gen, "noreturn.tsv"), encoding="utf-8") as fh:
            fh.readline()
            for line in fh:
                self.noreturn.add(int(line.split("\t")[0], 16))
        self.units = sorted(f for f in os.listdir(self.gen) if f.startswith("rfg_") and f.endswith(".c"))
        self.bodies = {}
        for u in self.units:
            for sub, b in split_bodies(open(os.path.join(self.gen, u), encoding="utf-8").read()).items():
                self.bodies[int(sub[4:], 16)] = b
        self.insns, self.commented, self.labelled = {}, {}, {}
        self.closure_added = 0

        def dec_at(a):
            raw = A.read(a, 16)
            d = next(_MD.disasm_lite(raw, a, 1), None) if raw else None
            return ((d[2] + (" " + d[3] if d[3] else "")).strip(), d[1]) if d else ("(undecodable)", 1)
        for va, b in self.bodies.items():
            lst = dict(body_insns(b))
            self.commented[va] = {a for a, t in lst.items() if t is not None}
            self.labelled[va] = {a for a, t in lst.items() if t is None}
            # fallthrough closure: the lifter also writes some instructions with neither comment nor label
            work = list(lst)
            while work:
                a = work.pop()
                t, size = dec_at(a)
                if lst[a] is None:
                    lst[a] = t
                mn, _, op = t.partition(" ")
                term = mn in ("ret", "retn", "jmp", "int3", "ud2", "hlt") or (
                    mn == "call" and re.fullmatch(r"0x[0-9a-f]+", op) and int(op, 16) in self.noreturn)
                ext = A.f.procs.get(va, {}).get("size", 0)
                if not term and a + size not in lst and a + size < va + ext and dec_at(a + size)[0] != "(undecodable)":
                    lst[a + size] = None
                    work.append(a + size)
                    self.closure_added += 1
            self.insns[va] = sorted(lst.items())
        A.pops = A.measure_pops(self.insns)
        A.procs_by_va = {va: (A.cnames.get("sub_%08X" % va) or nm[va][1]) for va in nm}
        A.pdb_name_of = {va: nm[va][1] for va in nm}
        A.vtable_va = {}
        for va, ns in A.f.publics.items():
            for n in ns:
                if n.startswith("??_7") and n.endswith("@@6B@"):
                    u = undecorate(n, full=False)
                    if u.endswith("::`vftable'"):
                        A.vtable_va.setdefault(u[:-len("::`vftable'")], va)
        A.block_starts = set()
        self.results = {}

    def compute(self, vas=None):
        A = self.A
        for va in (vas if vas is not None else sorted(self.bodies)):
            body = self.bodies[va]
            ins = self.insns[va]
            cases = sorted({int(c, 16) for c in CASE_RE.findall(body)})
            A.block_starts = {int(x, 16) for x in re.findall(r"^L_([0-9A-F]{8}):", body, re.M)} | set(cases)
            r = A.analyze(va, ins, cases, self.noreturn)
            if r is not None:
                r["label_only"] = self.labelled[va]
                for a, _ in ins:
                    if a not in self.commented[va] and a not in self.labelled[va]:
                        n = len(r["notes"].pop(a, ())) + len(r["pre"].pop(a, ()))
                        A.stats["annotations_unanchored"] += n
                        A.stats["insns_unanchored"] += 1
            self.results[va] = r
        return self.results


# ------------------------------------------------------------------------------------------ text apply/strip
def apply(body, sub, res, cnames, rel_path_of, group):
    """Insert annotations into one flat body (whose text has no '//' anywhere; checked by the caller).
    An instruction's anchor is its `/* 0xVA: asm */` comment (which must end its line), or, for an
    instruction the lifter wrote without one, its `L_VA:` label line. Line/label records go on their own
    `//` lines right before the statement (after its label); operand notes trail the anchor line."""
    out = []
    lines = body.split("\n")
    hdr_done = False
    pending = []        # lines of the current statement up to its anchor
    label_only = res["label_only"] if res else set()
    seen = set()
    for ln in lines:
        if not hdr_done and FN_RE.match(ln):
            out.append(ln)
            if res:
                for h in res["hdr"]:
                    out.append("    // " + h)
            hdr_done = True
            continue
        pending.append(ln)
        m = INSN_RE.search(ln)
        lm = LABEL_RE.match(ln)
        if m:
            a = int(m.group(1), 16)     # (mid-line comments are fine: notes go after the line's last token)
        elif lm and int(lm.group(1), 16) in label_only:
            a = int(lm.group(1), 16)
        else:
            continue
        if a in seen:
            out.extend(pending)
            pending = []
            continue
        seen.add(a)
        pre = res["pre"].get(a, []) if res else []
        notes = res["notes"].get(a, []) if res else []
        if notes:
            pending[-1] = pending[-1] + " // " + "; ".join(notes)
        if pre:
            k = len(pending) if lm and not m else 0     # label-only anchor: right after the label line
            if not (lm and not m):
                for q, pl in enumerate(pending[:-1]):
                    if not pl.strip() or LABEL_RE.match(pl):
                        k = q + 1
            ins_lines = []
            for p in pre:
                if p[0] == "line":
                    ins_lines.append(f"    // line {p[2]}" if p[1] == res["own_file"]
                                     else f"    // {rel_path_of(p[1])}:{p[2]}")
                else:
                    ins_lines.append(f"    // label {p[1]}")
            pending[k:k] = ins_lines
        out.extend(pending)
        pending = []
    out.extend(pending)
    text = "\n".join(out)
    return SUB_RE.sub(lambda mm: cnames.get("sub_" + mm.group(1), "sub_" + mm.group(1)), text)


STRIP_LINE = re.compile(r"^[ \t]*//[^\n]*\n", re.M)
STRIP_TAIL = re.compile(r" //[^\n]*")


def strip(text, rev):
    """Inverse of apply(): drop every // line and trailing // comment, map cnames back to sub_X."""
    text = STRIP_LINE.sub("", text)
    text = STRIP_TAIL.sub("", text)
    return IDENT_RE.sub(lambda m: rev.get(m.group(0), m.group(0)), text)


# ------------------------------------------------------------------------------------------ build
CLANG = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\bin\clang.exe"
PROFILES = (["-O1", "-DRECOMP_STRICT_ICALL"],                                            # build_host default
            ["-O2", "-DRECOMP_STRICT_ICALL", "-DRECOMP_MEM_QUAL=", "-DRECOMP_LOCAL_REGS"])  # --profile fast


def reserved_identifiers(root):
    """Every identifier and macro name a unit's compile sees, under both build_host profiles
    (preprocessed unit + -dM), plus every identifier in the flat units: a cname equal to one of these
    would change what the build means, so it gets the VA suffix."""
    gen = os.path.join(root, "gen")
    unit = os.path.join(gen, "rfg_0000.c")
    out = set(C_KEYWORDS)
    for prof in PROFILES:
        flags = ["--target=i686-pc-windows-msvc", "-w", "-fno-strict-aliasing", "-ffp-model=strict"] + prof + ["-I", os.path.join(root, "pcrecomp", "runtime", "recomp32"), "-I", gen]
        for extra in (["-E"], ["-E", "-dM"]):
            r = subprocess.run([CLANG] + flags + extra + [unit], capture_output=True, text=True, errors="replace")
            if r.returncode:
                raise SystemExit("ANNOTATE_PDB REFUSED: clang -E failed: " + r.stderr[-800:])
            ids = set(IDENT_RE.findall(r.stdout))
            if "RECOMP_CALL" not in ids and "-dM" in extra:
                raise SystemExit("ANNOTATE_PDB REFUSED: -dM output lacks RECOMP_CALL (control)")
            out |= ids
    for u in sorted(os.listdir(gen)):
        if u.endswith(".c") or u.endswith(".h"):
            out |= set(IDENT_RE.findall(open(os.path.join(gen, u), encoding="utf-8").read()))
    return out


def tree_path_fn(root):
    rs = []
    with open(os.path.join(root, "config", "source_roots.tsv"), encoding="utf-8") as f:
        f.readline()
        for line in f:
            p, t, _ = line.rstrip("\n").split("\t")
            rs.append((p.lower(), t))
    rs.sort(key=lambda x: -len(x[0]))
    memo = {}

    def rel(path):
        if path in memo:
            return memo[path]
        g = path.lower()
        r = path
        for p, t in rs:
            if g.startswith(p):
                r = t + g[len(p):].replace("\\", "/")
                break
        memo[path] = r
        return r
    return rel


def cmd_build(root):
    t0 = time.time()
    outdir = os.path.join(root, "config", "pdb_annot")
    os.makedirs(outdir, exist_ok=True)
    nm = []
    with open(os.path.join(root, "config", "names.tsv"), encoding="utf-8") as fh:
        fh.readline()
        for line in fh:
            va, cn, pdbn = line.rstrip("\n").split("\t")[:3]
            nm.append((int(va, 16), pdbn))
    reserved = reserved_identifiers(root)
    cn = assign_cnames(nm, reserved)
    # control: a reserved stem must be suffixed (the gate that keeps aliases from rewriting runtime code)
    ctrl = assign_cnames([(0x401000, "memcpy"), (0x401010, "eax")], reserved)
    ctrl_ok = ctrl[0x401000][0].endswith("_00401000") and ctrl[0x401010][0].endswith("_00401010")
    rules = collections.Counter(r for _, r in cn.values())
    p = os.path.join(outdir, "cnames.tsv")
    data = "va\tsub\tcname\trule\tpdb_name\n" + "".join(
        f"0x{va:08X}\tsub_{va:08X}\t{cn[va][0]}\t{cn[va][1]}\t{n}\n" for va, n in sorted(nm))
    old = open(p, encoding="utf-8").read() if os.path.exists(p) else None
    if old != data:
        open(p, "w", encoding="utf-8", newline="\n").write(data)
    print(json.dumps(dict(cnames=len(cn), rules=rules, reserved=len(reserved), control_reserved_suffixed=ctrl_ok,
                          cnames_changed=old != data), indent=1))
    if not ctrl_ok:
        sys.exit("ANNOTATE_PDB REFUSED: reserved-identifier control failed")
    P = Pass(root)
    P.compute()
    st = P.A.stats
    rec = coverage(P)
    rec["seconds"] = round(time.time() - t0, 1)
    rec["cnames"] = dict(total=len(cn), rules=dict(rules), reserved_identifiers=len(reserved))
    json.dump(rec, open(os.path.join(outdir, "receipt.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps(rec, indent=1, sort_keys=True))
    print("ANNOTATE_PDB BUILD DONE" if not st["insn_decode_mismatch"] else "ANNOTATE_PDB BUILD REFUSED")


def coverage(P):
    A, st = P.A, P.A.stats
    all_insn = {a for ins in P.insns.values() for a, _ in ins}
    line_starts = [a for a in A.f.lines]
    in_body = sum(1 for a in line_starts if a in all_insn)
    pre_lines = sum(sum(1 for x in r["pre"].get(a, ()) if x[0] == "line") for r in P.results.values() if r
                    for a in r["pre"])
    procs_with_body = sum(1 for va in P.bodies if va in A.f.procs)
    return dict(
        functions=len(P.bodies), functions_with_pdb_proc=procs_with_body,
        lines=dict(records=A.f.n_line_records, distinct_starts=len(line_starts), starts_on_lifted_insn=in_body,
                   annotations_written=pre_lines),
        frame=dict(fn_conflict=st["fn_frame_conflict"], records_placed=st["frame_records_placed"],
                   records_refused={k[len("frame_record_refused_"):]: v for k, v in st.items()
                                    if k.startswith("frame_record_refused_")},
                   stack_operands=st["stack_operands"], named=st["stack_operands_named"],
                   unnamed_slot=st["stack_operands_unnamed"], unknown_base=st["stack_operands_unknown_base"],
                   in_conflict_fn=st["stack_operands_conflict_fn"], ambiguous=st["stack_operands_ambiguous"]),
        data=dict(image_addr_operands=st["image_addr_operands"], named=st["image_addr_named"],
                  branch_targets=st["image_addr_branch_targets"], unresolved=st["image_addr_unresolved"]),
        icalls=dict(total=st["icalls"], import_=st["icalls_import"], virtual_named=st["icalls_virtual_named"],
                    typed=st["icalls_typed"], no_callsite=st["icalls_no_callsite"],
                    slot_type_mismatch=st["icalls_slot_type_mismatch"]),
        labels=len(A.f.labels), insn_decode_mismatch=st["insn_decode_mismatch"],
        stats=dict(sorted(st.items())), closure_added_insns=getattr(P, "closure_added", None))


if __name__ == "__main__":
    if sys.argv[1] == "build":
        cmd_build(os.path.abspath(sys.argv[2]))
    else:
        sys.exit("usage: see module docstring")
