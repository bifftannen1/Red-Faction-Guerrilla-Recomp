"""C++ headers for every type rfg.pdb's TPI records, with static_assert on every size and offset.

Writes <out>/rfg_types.hpp (every enum, then every struct/class/union in dependency order) and
<out>/rfg_protos.hpp (one prototype per lifted procedure, named by config/pdb_annot/cnames.tsv).
Layout is exact by construction and proven by the compiler: `#pragma pack(1)`, every member placed at
its TPI offset with explicit `uint8_t` padding, bit-fields in whole storage units, the tail padded
to the TPI size; a UDT whose members overlap (anonymous unions MSVC flattened into the field list)
is emitted in overlay form (each member in its own padded struct inside one anonymous union). Every
complete UDT gets static_assert(sizeof) and every non-bit-field data member static_assert(offsetof).
Names: '::' -> '__', other non-identifier runs -> '_', <unnamed-...> -> anon_<TI>; two different
layouts under one name -> the later ones get __ti<TI>; types are always written elaborated
(`struct X`, `enum X`) so a member or function named like a type never changes its meaning.
What is NOT recreated: methods/virtual functions as C++ members (the vtable is `void **__vfptr`),
virtual-base subobjects (left as padding, counted), static members (listed as comments).
Gates (refuse, exit 1): clang++ -fsyntax-only (i686-pc-windows-msvc, C++17) compiles both headers with
every static_assert; controls: a copy with one sizeof value +1 and a copy with one offsetof value +1
must each FAIL to compile. Second run changes 0 files.
Usage: python -X utf8 -P tools/pdb_headers.py <rfg_pc_recomp> <out_dir>
Marker: PDB_HEADERS DONE
"""
import collections, json, os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT, OUT = map(os.path.abspath, sys.argv[1:3])
sys.path.insert(0, HERE)
from pdb_tpi import Pdb, BASIC  # noqa: E402
from annotate_pdb import CLANG, CC_NAME, proc_args, load_methodlists  # noqa: E402

CLANGXX = CLANG.replace("clang.exe", "clang++.exe")
UDT = (0x1504, 0x1505, 0x1506, 0x1519)
KW = set("""alignas alignof and and_eq asm auto bitand bitor bool break case catch char char16_t char32_t class
compl const constexpr const_cast continue decltype default delete do double dynamic_cast else enum explicit
export extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr
operator or or_eq private protected public register reinterpret_cast return short signed sizeof static
static_assert static_cast struct switch template this thread_local throw true try typedef typeid typename union
unsigned using virtual void volatile wchar_t while xor xor_eq int8_t int16_t int32_t int64_t uint8_t uint16_t
uint32_t uint64_t size_t offsetof NULL max min interface""".split())

pdb = Pdb(os.path.join(ROOT, "input", "rfg.pdb"))
tpi = pdb.tpi
tpi.mlists = load_methodlists(pdb)
stats = collections.Counter()


def ident(s):
    s = s.replace("::", "__").replace("*", "_p").replace("&", "_r")
    s = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_") or "anon"
    if s[0].isdigit():
        s = "t_" + s
    return s


# ---------------------------------------------------------------- name every defining UDT / enum record
defs = [t for t, (leaf, r) in tpi.recs.items() if leaf in UDT + (0x1507,) and not r.get("fwd")]
by_stem = collections.defaultdict(list)
for t in sorted(defs):
    leaf, r = tpi.rec(t)
    nm = r["name"]
    stem = f"anon_{t:X}" if nm.startswith("<unnamed") or nm.startswith("__unnamed") or nm.startswith("<lambda") \
        else ident(nm)
    if stem in KW:
        stem += "_t"
    by_stem[stem].append(t)


def signature(t):
    leaf, r = tpi.rec(t)
    fl = tuple((f["k"], f.get("offset"), f.get("name"), tpi.name(f["type"]) if "type" in f else None)
               for f in tpi.fields(t) if f["k"] in ("member", "base", "vbase", "vfptr", "enumerate"))
    if leaf == 0x1507:
        fl = tuple((f["name"], f["value"]) for f in tpi.fields(t) if f["k"] == "enumerate")
    return (leaf, r.get("size"), fl)


emit_name = {}     # defining TI -> emitted identifier
canonical = {}     # defining TI -> TI that is emitted (identical layouts share one definition)
taken = set()
for stem, ts in sorted(by_stem.items()):
    sigs = {}
    for t in ts:
        s = signature(t)
        if s in sigs:
            canonical[t] = sigs[s]
            stats["duplicate_identical_definitions"] += 1
            continue
        sigs[s] = t
        canonical[t] = t
        name = stem if len(sigs) == 1 else f"{stem}__ti{t:X}"
        if len(sigs) > 1:
            stats["distinct_layouts_same_name"] += 1
        while name in taken:
            name += "_"
        taken.add(name)
        emit_name[t] = name


def canon(ti):
    """Any UDT/enum type index (forward refs included) -> the emitted defining TI, or None."""
    d = tpi.resolve(ti)
    leaf, r = tpi.rec(d)
    if leaf in UDT + (0x1507,) and not r.get("fwd"):
        return canonical[d]
    return None


fwd_only = {}       # forward-only UDT/enum (never defined): emitted as incomplete types


def type_ref(ti):
    """Elaborated name of a UDT/enum type."""
    d = canon(ti)
    leaf, r = tpi.rec(tpi.resolve(ti))
    if d is None:
        nm = r.get("name", "anon")
        key = ident(nm) + "__fwd"
        fwd_only.setdefault(key, leaf)
        kw = "union" if leaf == 0x1506 else "enum" if leaf == 0x1507 else "struct"
        return f"{kw} {key}"
    kw = "union" if tpi.rec(d)[0] == 0x1506 else "enum" if tpi.rec(d)[0] == 0x1507 else "struct"
    return f"{kw} {emit_name[d]}"


def basic(ti):
    b = ti & 0xFF
    if b == 0x03 and not (ti >> 8) & 0xF:
        return "void"
    return BASIC.get(b, ("uint8_t", 1))[0] if b in BASIC else None


def decl(ti, name, depth=0):
    """C++ declarator for type `ti` declaring `name`; None when the type cannot be spelled."""
    if depth > 30:
        return None
    if ti < 0x1000:
        mode = (ti >> 8) & 0xF
        b = basic(ti & 0xFF)
        if b is None:
            return None
        if b == "long double":
            return None
        return f"{b} *{name}" if mode else f"{b} {name}".rstrip()
    leaf, r = tpi.rec(ti)
    if leaf == 0x1001:
        inner = r["type"]
        il = tpi.rec(inner)[0] if inner >= 0x1000 else None
        q = ("const " if r["const"] else "") + ("volatile " if r["volatile"] else "")
        if il == 0x1002 or (inner < 0x1000 and (inner >> 8) & 0xF):
            return decl(inner, q + name, depth + 1)
        d = decl(inner, name, depth + 1)
        return None if d is None else q + d
    if leaf == 0x1002:
        if r["mode"] in (2, 3):             # pointer to data member / member function
            return None
        star = "&" if r["mode"] in (1, 4) else "*"
        pt = tpi.strip(r["type"])
        pl = tpi.rec(pt)[0] if pt >= 0x1000 else None
        inner = f"{star}{name}"
        if pl in (0x1503, 0x1008, 0x1009):
            inner = f"({inner})"
        if star == "&":     # references as struct members are pointers in memory
            inner = inner.replace("&", "*", 1)
        return decl(r["type"], inner, depth + 1)
    if leaf == 0x1503:
        es = tpi.sizeof(r["elem"])
        if not es:
            return None
        return decl(r["elem"], f"{name}[{r['size'] // es}]", depth + 1)
    if leaf in (0x1008, 0x1009):
        args = proc_args(tpi, ti)
        if args is None:
            return None
        ps = []
        if leaf == 0x1009 and r["this"]:
            t = decl(r["this"], "this_", depth + 1)
            if t is None:
                return None
            ps.append(t)
        for k, a in enumerate(args):
            if a == 0:
                ps.append("...")
                continue
            d = decl(a, f"a{k}", depth + 1)
            if d is None:
                return None
            ps.append(d)
        cc = CC_NAME.get(r["cc"])
        if cc is None or cc == "__clrcall":
            return None
        if leaf == 0x1009 and cc == "__thiscall" and not ps:
            return None
        return decl(r["rv"], f"{cc} {name}({', '.join(ps) or 'void'})", depth + 1)
    if leaf in UDT + (0x1507,):
        return f"{type_ref(ti)} {name}".rstrip()
    return None


def tsize(ti):
    return tpi.sizeof(ti)


# ---------------------------------------------------------------- layout one UDT
def layout(t):
    """-> (body lines, asserts, deps). deps = TIs needed complete (by-value)."""
    leaf, r = tpi.rec(t)
    size = r["size"]
    name = emit_name[t]
    items, deps, comments = [], set(), []
    used = collections.Counter()

    def mname(n):
        n = ident(n) if n else "m"
        if n in KW:
            n += "_"
        used[n] += 1
        return n if used[n] == 1 else f"{n}_{used[n]}"
    fields = tpi.fields(t)
    for f in fields:
        k = f["k"]
        if k == "member":
            ft = f["type"]
            fl = tpi.rec(ft)[0] if ft >= 0x1000 else None
            if fl == 0x1205:
                br = tpi.rec(ft)[1]
                items.append(dict(off=f["offset"], size=tsize(br["type"]), bit=(br["pos"], br["length"]),
                                  btype=br["type"], name=mname(f["name"])))
                continue
            sz = tsize(ft)
            nm = mname(f["name"])
            d = decl(ft, nm)
            if d is None:
                d = f"uint8_t {nm}[{max(sz, 1)}]"
                stats["members_as_bytes"] += 1
            for dep in by_value_deps(ft):
                deps.add(dep)
            items.append(dict(off=f["offset"], size=sz, decl=d, name=nm, assert_off=True))
        elif k == "base":
            bt = f["type"]
            sz = tsize(bt)
            d = canon(bt)
            if d is None or not sz:
                stats["bases_unsized"] += 1
                continue
            if not any(x["k"] in ("member", "base", "vfptr") for x in tpi.fields(d)) and sz == 1:
                stats["empty_bases_omitted"] += 1
                comments.append(f"empty base {emit_name[d]}")
                continue
            nm = mname("base_" + emit_name[d])
            deps.add(d)
            items.append(dict(off=f["offset"], size=sz, decl=f"{type_ref(bt)} {nm}", name=nm, assert_off=True))
        elif k == "vbase":
            stats["virtual_bases_as_padding"] += 1
            comments.append(f"virtual base {type_ref(f['type'])} (location is per object; padding here)")
        elif k == "vfptr":
            items.append(dict(off=0, size=4, decl="void **__vfptr", name="__vfptr", vfptr=True, assert_off=True))
        elif k == "static":
            comments.append(f"static {tpi.name(f['type'])} {f['name']}")
    # a vfptr only belongs at 0 when nothing else starts there
    if any(i.get("vfptr") for i in items) and any(i["off"] == 0 and not i.get("vfptr") for i in items):
        items = [i for i in items if not i.get("vfptr")]
        stats["vfptr_in_base"] += 1
    return items, deps, comments


def by_value_deps(ti, depth=0):
    if ti < 0x1000 or depth > 30:
        return []
    leaf, r = tpi.rec(ti)
    if leaf == 0x1001:
        return by_value_deps(r["type"], depth + 1)
    if leaf == 0x1503:
        return by_value_deps(r["elem"], depth + 1)
    if leaf in UDT:
        d = canon(ti)
        return [d] if d is not None else []
    return []


def render_seq(items, size, is_union):
    """Sequential layout; None when members overlap (caller uses the overlay form)."""
    out, cur, k = [], 0, 0
    items = sorted(items, key=lambda i: (i["off"], i.get("bit", (0, 0))[0]))
    if is_union:
        for i in items:
            if i["off"] or "bit" in i:
                return None
            out.append(f"    {i['decl']};")
        return out
    j = 0
    while j < len(items):
        i = items[j]
        if i["off"] < cur:
            return None
        if i["off"] > cur:
            out.append(f"    uint8_t _pad{k}[{i['off'] - cur}];")
            k += 1
        if "bit" in i:
            grp = [i]
            while j + 1 < len(items) and "bit" in items[j + 1] and items[j + 1]["off"] == i["off"]:
                j += 1
                grp.append(items[j])
            out.extend(render_bits(grp))
            cur = i["off"] + i["size"]
        else:
            out.append(f"    {i['decl']};")
            cur = i["off"] + i["size"]
        j += 1
    if cur > size:
        return None
    if cur < size:
        out.append(f"    uint8_t _pad{k}[{size - cur}];")
    return out


def render_bits(grp):
    bt = grp[0]["btype"]
    tn = decl(bt, "").strip() if decl(bt, "") else "uint32_t"
    width = tsize(bt) * 8
    out, pos = [], 0
    for g in sorted(grp, key=lambda g: g["bit"][0]):
        p, ln = g["bit"]
        if p > pos:
            out.append(f"    {tn} : {p - pos};")
        out.append(f"    {tn} {g['name']} : {ln};")
        pos = p + ln
    if pos < width:
        out.append(f"    {tn} : {width - pos};")
    stats["bitfield_members"] += len(grp)
    return out


def render_overlay(items, size):
    out = ["    union {"]
    groups = collections.OrderedDict()
    for i in sorted(items, key=lambda i: (i["off"], i.get("bit", (0, 0))[0])):
        key = ("bits", i["off"]) if "bit" in i else ("m", i["name"])
        groups.setdefault(key, []).append(i)
    for n, (key, g) in enumerate(groups.items()):
        off = g[0]["off"]
        body = render_bits(g) if key[0] == "bits" else [f"    {g[0]['decl']};"]
        pad = [f"        uint8_t _o{n}[{off}];"] if off else []   # anonymous-struct members share one scope
        out.append("        struct {")
        out.extend(pad)
        out.extend("    " + b for b in body)
        out.append("        };")
    out.append(f"        uint8_t _size[{size}];")
    out.append("    };")
    return out


def main():
    t0 = time.time()
    os.makedirs(OUT, exist_ok=True)
    enums, udts = [], []
    for t in sorted(emit_name):
        (enums if tpi.rec(t)[0] == 0x1507 else udts).append(t)
    lay = {}
    for t in udts:
        lay[t] = layout(t)
    # dependency order (by-value), deterministic
    order, state = [], {}

    def visit(t):
        if state.get(t) == 2:
            return
        if state.get(t) == 1:
            raise SystemExit(f"PDB_HEADERS REFUSED: by-value cycle at {t:#x}")
        state[t] = 1
        for d in sorted(lay[t][1]):
            if d != t and d in lay:
                visit(d)
        state[t] = 2
        order.append(t)
    sys.setrecursionlimit(100000)
    for t in udts:
        visit(t)
    L = ["// Generated by tools/pdb_headers.py from rfg.pdb TPI. DO NOT EDIT.",
         "// Every size and offset below is a static_assert against the PDB record.",
         "#pragma once", "#include <stdint.h>", "#include <stddef.h>", "#pragma pack(push, 1)", ""]
    body_udts, asserts = [], []
    n_size = n_off = 0
    for t in enums:
        leaf, r = tpi.rec(t)
        ut = decl(r["utype"], "").strip() if r["utype"] else "int32_t"
        vals, seen = [], collections.Counter()
        for f in tpi.fields(t):
            if f["k"] != "enumerate":
                continue
            n = ident(f["name"])
            if n in KW:
                n += "_"
            seen[n] += 1
            if seen[n] > 1:
                n = f"{n}_{seen[n]}"
            vals.append(f"    {n} = static_cast<{ut}>({f['value']}),")
        L.append(f"// {r['name']}  (TI {t:#x})")
        L.append(f"enum class {emit_name[t]} : {ut} {{")
        L.extend(vals)
        L.append("};")
        stats["enums"] += 1
    L.append("")
    fwd_lines = []
    for t in order:
        leaf, r = tpi.rec(t)
        items, deps, comments = lay[t]
        name = emit_name[t]
        kw = "union" if leaf == 0x1506 else "struct"
        size = r["size"]
        fwd_lines.append(f"{kw} {name};")
        if size == 0:
            body_udts.append(f"{kw} {name} {{}};  // TPI size 0")
            stats["udts_size0"] += 1
            continue
        body = render_seq(items, size, leaf == 0x1506)
        if body is None:
            body = render_overlay(items, size)
            stats["udts_overlay"] += 1
            kw = "struct" if leaf != 0x1506 else "union"
        if leaf == 0x1506 and not any("_size" in b for b in body):
            body.append(f"    uint8_t _size[{size}];")
        body_udts.append(f"// {r['name']}  (TI {t:#x}, {r['kind']}, {size} bytes)")
        body_udts.extend(f"//   {c}" for c in comments)
        body_udts.append(f"{kw} {name} {{")
        body_udts.extend(body)
        body_udts.append("};")
        asserts.append(f"static_assert(sizeof({kw} {name}) == {size}, \"{name}\");")
        n_size += 1
        for i in items:
            if i.get("assert_off") and "bit" not in i:
                asserts.append(f"static_assert(offsetof({kw} {name}, {i['name']}) == {i['off']}, \"{name}.{i['name']}\");")
                n_off += 1
        stats["udts"] += 1
    for key, leaf in sorted(fwd_only.items()):
        fwd_lines.append(f"{'union' if leaf == 0x1506 else 'enum class' if leaf == 0x1507 else 'struct'} {key}"
                         + (" : int32_t;" if leaf == 0x1507 else ";"))
    L.extend(fwd_lines)
    L.append("")
    L.extend(body_udts)
    L.append("")
    L.append("#pragma pack(pop)")
    L.extend(asserts)
    text = "\n".join(L) + "\n"
    # prototypes
    cn = {}
    with open(os.path.join(ROOT, "config", "pdb_annot", "cnames.tsv"), encoding="utf-8") as f:
        f.readline()
        for line in f:
            va, sub, c, rule, pn = line.rstrip("\n").split("\t")
            cn[int(va, 16)] = (c, pn)
    P = ["// Generated by tools/pdb_headers.py: one prototype per lifted procedure, from its PDB type.",
         "// Names are config/pdb_annot/cnames.tsv; member functions take `this_` first.",
         "#pragma once", "#include \"rfg_types.hpp\"", ""]
    proc_t = {}
    for va, size, name, typ, kind, mod in pdb.procs():
        proc_t.setdefault(va, typ)
    for va in sorted(cn):
        c, pn = cn[va]
        typ = proc_t.get(va)
        d = decl(typ, c) if typ else None
        if d is None:
            P.append(f"// {va:#010x} {pn}: no prototype (type {typ:#x} not spellable)" if typ else
                     f"// {va:#010x} {pn}: no PDB type")
            stats["protos_missing"] += 1
            continue
        P.append(f"{d};  // {va:#010x} {pn}")
        stats["protos"] += 1
    ptext = "\n".join(P) + "\n"
    changed = 0
    for fn, data in (("rfg_types.hpp", text), ("rfg_protos.hpp", ptext)):
        p = os.path.join(OUT, fn)
        if not os.path.exists(p) or open(p, encoding="utf-8").read() != data:
            open(p, "w", encoding="utf-8", newline="\n").write(data)
            changed += 1
    # gate: compile, then two controls that must fail
    def compile_(path):
        r = subprocess.run([CLANGXX, "--target=i686-pc-windows-msvc", "-std=c++17", "-fsyntax-only", "-ferror-limit=20",
                            "-Wno-everything", "-x", "c++", path], capture_output=True, text=True, errors="replace")
        return r.returncode, r.stderr
    rc, err = compile_(os.path.join(OUT, "rfg_protos.hpp"))
    ctrl = {}
    work = os.path.join(ROOT, "work", "pdb_headers_ctrl")
    os.makedirs(work, exist_ok=True)
    for kind, pat in (("sizeof", r"(static_assert\(sizeof\([^)]*\) == )(\d+)"),
                      ("offsetof", r"(static_assert\(offsetof\([^)]*\) == )(\d+)")):
        m = list(re.finditer(pat, text))
        m = m[len(m) // 2]
        bad = text[:m.start(2)] + str(int(m.group(2)) + 1) + text[m.end(2):]
        cp = os.path.join(work, f"ctrl_{kind}.hpp")
        open(cp, "w", encoding="utf-8", newline="\n").write(bad)
        crc, cerr = compile_(cp)
        ctrl[kind] = dict(line=m.group(0)[:120], failed=crc != 0, error=cerr.strip().splitlines()[0][:200] if cerr else "")
    rec = dict(stats=dict(stats), static_asserts=dict(sizeof=n_size, offsetof=n_off), compile_rc=rc,
               compile_errors=err.strip().splitlines()[:20], controls=ctrl, files_changed=changed,
               tpi_records=tpi.count, udt_defs=len([t for t in defs if tpi.rec(t)[0] in UDT]),
               enum_defs=len([t for t in defs if tpi.rec(t)[0] == 0x1507]), seconds=round(time.time() - t0, 1))
    json.dump(rec, open(os.path.join(OUT, "headers_receipt.json"), "w"), indent=1, sort_keys=True)
    print(json.dumps(rec, indent=1, sort_keys=True))
    print(f"files changed: {changed}")
    ok = rc == 0 and all(c["failed"] for c in ctrl.values())
    print("PDB_HEADERS DONE" if ok else "PDB_HEADERS REFUSED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
