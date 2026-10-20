"""RFG PC codegen: lift every PDB procedure of rfg.exe with pcrecomp lift32.

Function list = feed/procs.tsv (PDB procedures and thunks, exact extents) + declared interior
entries (feed/interior_entries.tsv). Each body is the set of instructions reachable from its entry
inside its PDB extent:
  * direct branches;
  * `jmp [idx*4 + T]` arms, bounded by the MSVC guard `cmp idx, N; ja` (or the max of a
    `movzx idx, byte [B + idx]` index table); unguarded tables read until the first arm outside
    the extent (counted and reported);
  * no fall-through after a call to a NORETURN target. NORETURN is computed, not listed: seeded
    with the exit-type imports (exit, _exit, abort, ExitProcess, ExitThread, _endthreadex,
    _CxxThrowException, _invalid_parameter_noinfo_noreturn, longjmp), then a fixpoint over
    procedures whose reachable body has no ret, no tail jump and no indirect jump.

Gates (refuse on failure):
  * every direct call/jmp target outside the current body must be a catalog start, or an import;
    anything else is a RESIDUAL and the run refuses unless --allow-residual;
  * every lifted body must carry zero RECOMP_UNIMPL unless --allow-unimpl (counted per form);
  * a lift exception is a refusal.
Outputs (outdir): rfg_NNNN.c chunks, recomp_funcs.h, recomp_dispatch.c, codegen_receipt.json,
residual.tsv, noreturn.tsv, unimpl.tsv. Marker on success: RFG_CODEGEN DONE.
Usage: python -X utf8 rfg_codegen.py <pcrecomp> <exe> <feed_dir> <outdir> [--chunk 400]
       [--limit N] [--jobs J] [--allow-residual] [--allow-unimpl]
"""
import collections, hashlib, json, os, re, struct, sys, time
from concurrent.futures import ProcessPoolExecutor

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FLAGS = [a for a in sys.argv[1:] if a.startswith("--")]
PCRECOMP, EXE, FEED, OUT = map(os.path.abspath, ARGS[:4])


def flag_val(name, default):
    for i, a in enumerate(sys.argv):
        if a == name and i + 1 < len(sys.argv):
            return int(sys.argv[i + 1])
    return default


CHUNK = flag_val("--chunk", 400)
LIMIT = flag_val("--limit", 0)
JOBS = flag_val("--jobs", max(1, (os.cpu_count() or 2) - 1))
ALLOW_RESIDUAL = "--allow-residual" in FLAGS
ALLOW_UNIMPL = "--allow-unimpl" in FLAGS

for sub in ("tools/lift", "tools/disasm", "tools/pe"):
    sys.path.insert(0, os.path.join(PCRECOMP, *sub.split("/")))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG  # noqa: E402

NORETURN_IMPORTS = {"exit", "_exit", "abort", "ExitProcess", "ExitThread", "_endthreadex", "_endthread",
                    "_CxxThrowException", "_invalid_parameter_noinfo_noreturn", "longjmp", "FatalAppExitA",
                    "FatalExit", "terminate", "?terminate@@YAXXZ", "_amsg_exit"}

# ----------------------------------------------------------------------------------- image
DATA = open(EXE, "rb").read()
_pe = struct.unpack_from("<I", DATA, 0x3C)[0]
_nsec = struct.unpack_from("<H", DATA, _pe + 6)[0]
_optsz = struct.unpack_from("<H", DATA, _pe + 20)[0]
BASE = struct.unpack_from("<I", DATA, _pe + 24 + 28)[0]
SECS = [struct.unpack_from("<8sIIII", DATA, _pe + 24 + _optsz + 40 * i) for i in range(_nsec)]


def read_va(va, n):
    rva = va - BASE
    for _nm, vs, sva, rs, rp in SECS:
        if sva <= rva < sva + vs:
            o = rva - sva
            b = DATA[rp + o:rp + min(o + n, rs)]
            return b + b"\0" * (n - len(b))
    raise ValueError(hex(va))


def load_catalog():
    funcs = []
    with open(os.path.join(FEED, "procs.tsv"), encoding="utf-8") as f:
        f.readline()
        for line in f:
            va, size, kind, name, *_ = line.rstrip("\n").split("\t")
            funcs.append((int(va, 16), int(size), kind, name))
    p = os.path.join(FEED, "interior_entries.tsv")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            f.readline()
            for line in f:
                va, size, kind, name = line.rstrip("\n").split("\t")[:4]
                funcs.append((int(va, 16), int(size), kind, name))
    funcs.sort()
    if LIMIT:
        funcs = funcs[:LIMIT]
    return funcs


def iat_map():
    from pe_analyze import analyze_pe, build_iat_map
    return build_iat_map(analyze_pe(EXE))


# ----------------------------------------------------------------------------------- walker
_md = None


def md():
    global _md
    if _md is None:
        _md = Cs(CS_ARCH_X86, CS_MODE_32)
        _md.detail = True
    return _md


def guard_bound(prev, idx_reg):
    reg, byte_table = idx_reg, None
    for ins in reversed(prev[-12:]):
        ops = ins.operands
        if (ins.mnemonic == "movzx" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[0].reg == reg
                and ops[1].type == X86_OP_MEM and ops[1].size == 1):
            byte_table = ops[1].mem.disp & 0xFFFFFFFF
            reg = ops[1].mem.index or ops[1].mem.base
            continue
        if (ins.mnemonic == "cmp" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[0].reg == reg
                and ops[1].type == X86_OP_IMM):
            n = ops[1].imm & 0xFFFFFFFF
            if n > 4096:
                return None
            if byte_table is not None:
                return max(read_va(byte_table, n + 1)) + 1
            return n + 1
    return None


def walk(va, size, noreturn, iat):
    """Reachable instructions of one body. Returns (insns, arms, info)."""
    code = read_va(va, size)
    m = md()
    seen, work, arms = {}, [va], set()
    info = dict(tables=0, tables_unguarded=0, may_return=False, calls=[], jumps_out=[], noreturn_stops=0)
    while work:
        a = work.pop()
        while va <= a < va + size and a not in seen:
            ins = next(m.disasm(code[a - va:a - va + 16], a, count=1), None)
            if ins is None:
                info.setdefault("decode_stops", 0)
                info["decode_stops"] = info.get("decode_stops", 0) + 1
                break
            seen[a] = ins
            mn = ins.mnemonic.split()[-1]
            ops = ins.operands
            if mn in ("ret", "retn", "retf"):
                info["may_return"] = True
                break
            if mn in ("hlt", "ud2", "int3"):
                break
            if mn == "call":
                tgt = None
                if ops and ops[0].type == X86_OP_IMM:
                    tgt = ops[0].imm & 0xFFFFFFFF
                    info["calls"].append(tgt)
                elif ops and ops[0].type == X86_OP_MEM and not ops[0].mem.base and not ops[0].mem.index:
                    tgt = ops[0].mem.disp & 0xFFFFFFFF
                if tgt is not None and tgt in noreturn:
                    info["noreturn_stops"] += 1
                    break
            elif ins.mnemonic.startswith("j") or mn.startswith("loop"):
                op = ops[0] if ops else None
                if op is not None and op.type == X86_OP_IMM:
                    t = op.imm & 0xFFFFFFFF
                    if va <= t < va + size:
                        work.append(t)
                    else:
                        info["jumps_out"].append(t)
                        # A jump out of the extent, conditional or not, hands control to another
                        # body (a tail call, or asm CRT code like _ftol2_sse's `je _ftol2`): the
                        # function may return through it unless that target is itself noreturn.
                        if t not in noreturn:
                            info["may_return"] = True
                elif op is not None and op.type == X86_OP_MEM and op.mem.index and op.mem.scale == 4 and not op.mem.base:
                    info["tables"] += 1
                    t0 = op.mem.disp & 0xFFFFFFFF
                    nb = guard_bound(sorted(seen.values(), key=lambda i: i.address), op.mem.index)
                    if nb is None:
                        info["tables_unguarded"] += 1
                    k = 0
                    while k < (nb if nb is not None else 1024):
                        t = struct.unpack("<I", read_va(t0 + 4 * k, 4))[0]
                        if not (va <= t < va + size):
                            break
                        work.append(t)
                        arms.add(t)
                        k += 1
                elif ins.mnemonic == "jmp":
                    if op is not None and op.type == X86_OP_MEM and not op.mem.base and not op.mem.index \
                            and (op.mem.disp & 0xFFFFFFFF) in noreturn:
                        info["noreturn_stops"] += 1
                    else:
                        info["may_return"] = True        # jmp reg / jmp [mem]: unknown, assume returns
                if ins.mnemonic == "jmp":
                    break
            a = ins.address + ins.size
            if not (va <= a < va + size):
                # Fell off the end of the PDB extent into the next procedure (MSVC CRT asm:
                # _ftol2_sse, 9 bytes, runs on into _ftol2_pentium4). Control continues there,
                # so this is a way out of the function, not a dead end.
                info.setdefault("fall_out", []).append(a)
                if a not in noreturn:
                    info["may_return"] = True
    return [seen[k] for k in sorted(seen)], arms, info


# ----------------------------------------------------------------------------------- phase A: noreturn fixpoint
_NR = {}


def _nr_init(nr, iat):
    _NR.update(nr=nr, iat=iat)


def _nr_batch(batch):
    nr, iat = _NR["nr"], _NR["iat"]
    return [va for va, size, kind, name in batch
            if va not in nr and not walk(va, size, nr, iat)[2]["may_return"]]


def _calls_batch(batch):
    nr, iat = _NR["nr"], _NR["iat"]
    out = []
    for va, size, kind, name in batch:
        out.extend(walk(va, size, nr, iat)[2]["calls"])
    return out


def call_into_body_entries(funcs, nr, iat):
    """Direct `call` targets that land inside a catalog function but not on its start: MSVC x86
    __finally funclets (`call $LN_finally` in the same body) and other local call targets. Each
    becomes an interior entry (evidence CALL_INTO_BODY) running to the end of its parent's extent;
    without it lift32 degrades the call to an ICALL that misses at run time and returns 0."""
    import bisect
    starts = [f[0] for f in funcs]
    batches = [funcs[i:i + 1000] for i in range(0, len(funcs), 1000)]
    targets = set()
    with ProcessPoolExecutor(max_workers=JOBS, initializer=_nr_init, initargs=(nr, iat)) as ex:
        for res in ex.map(_calls_batch, batches):
            targets.update(res)
    have = set(starts)
    extra = []
    for t in sorted(targets - have):
        i = bisect.bisect_right(starts, t) - 1
        if i >= 0 and t < funcs[i][0] + funcs[i][1]:
            pva, psz, _k, pname = funcs[i]
            extra.append((t, pva + psz - t, "CALL_INTO_BODY", f"{pname}+0x{t - pva:X}"))
    return extra


def noreturn_fixpoint(funcs, iat):
    nr = {va for va, (dll, fn) in iat.items() if fn in NORETURN_IMPORTS}
    seeds = {hex(va): iat[va][1] for va in nr}
    rounds = []
    batches = [funcs[i:i + 1000] for i in range(0, len(funcs), 1000)]
    while True:
        t = time.time()
        new = set()
        with ProcessPoolExecutor(max_workers=JOBS, initializer=_nr_init, initargs=(nr, iat)) as ex:
            for res in ex.map(_nr_batch, batches):
                new.update(res)
        added = new - nr
        rounds.append(len(added))
        print(f"[A] noreturn round {len(rounds)}: +{len(added)} ({time.time() - t:.0f}s)", flush=True)
        nr |= new
        if not added or len(rounds) > 8:
            break
    return nr, seeds, rounds


# ----------------------------------------------------------------------------------- phase B: lift (workers)
_W = {}


def _init(lifted, noreturn, iat):
    import lift32, generate  # noqa: F401
    _W.update(lifted=lifted, noreturn=noreturn, iat=iat, lift32=lift32, generate=generate)


def lift_batch(batch):
    lift32, generate = _W["lift32"], _W["generate"]
    lifted, noreturn, iat = _W["lifted"], _W["noreturn"], _W["iat"]
    out = []
    for va, size, kind, name in batch:
        insns, arms, info = walk(va, size, noreturn, iat)
        li = [generate.LinearInstruction(i) for i in insns]
        leaders = {va} | arms
        for k, i in enumerate(li):
            if i.is_jump or i.is_ret or i.is_call:
                t = i.get_branch_target()
                if i.is_jump and t is not None and va <= t < va + size:
                    leaders.add(t)
                if k + 1 < len(li):
                    leaders.add(li[k + 1].address)
        cname = "sub_%08X" % va
        err = None
        try:
            L = lift32.Lifter(iat_map=iat, lifted=lifted)
            c = generate.lift_function_linear(L, cname, li, leaders, va, indirect_targets=arms or None)
        except Exception as e:  # refusal recorded per function
            c, err = "", "%s: %s" % (type(e).__name__, str(e)[:200])
        unimpl = re.findall(r'RECOMP_UNIMPL\(0x([0-9A-F]{8})u, "([^"]*)"', c)
        resid = [t for t in info["calls"] + info["jumps_out"] if t not in lifted and t not in iat]
        out.append(dict(va=va, size=size, name=name, cname=cname, code=c, err=err, n_insns=len(insns),
                        unimpl=unimpl, residual=resid, tables=info["tables"],
                        tables_unguarded=info["tables_unguarded"], noreturn_stops=info["noreturn_stops"],
                        decode_stops=info.get("decode_stops", 0)))
    return out


def main():
    t0 = time.time()
    os.makedirs(OUT, exist_ok=True)
    funcs = load_catalog()
    iat = iat_map()
    nr, seeds, rounds = noreturn_fixpoint(funcs, iat)
    print(f"[A] catalog {len(funcs)}; iat {len(iat)}; noreturn seeds {len(seeds)} {sorted(seeds.values())}; "
          f"fixpoint added per round {rounds}; noreturn total {len(nr)}", flush=True)
    extra = call_into_body_entries(funcs, nr, iat)
    print(f"[A] call-into-body interior entries: {len(extra)} {[(hex(e[0]), e[3]) for e in extra[:6]]}", flush=True)
    with open(os.path.join(OUT, "interior_calls.tsv"), "w", encoding="utf-8") as w:
        w.write("va\tsize\tkind\tname\n")
        for e in extra:
            w.write(f"0x{e[0]:08X}\t{e[1]}\t{e[2]}\t{e[3]}\n")
    funcs = sorted(funcs + extra)
    names = {va: name for va, _s, _k, name in funcs}
    with open(os.path.join(OUT, "noreturn.tsv"), "w", encoding="utf-8") as w:
        w.write("va\tname\n")
        for va in sorted(nr):
            w.write(f"{va:#010x}\t{names.get(va) or iat.get(va, ('', ''))[1]}\n")
    lifted = {va for va, *_ in funcs}
    batches = [funcs[i:i + 200] for i in range(0, len(funcs), 200)]
    results = []
    with ProcessPoolExecutor(max_workers=JOBS, initializer=_init, initargs=(lifted, nr, iat)) as ex:
        for k, res in enumerate(ex.map(lift_batch, batches)):
            results.extend(res)
            if k % 50 == 0:
                print(f"[B] {len(results)}/{len(funcs)} lifted ({time.time() - t0:.0f}s)", flush=True)
    results.sort(key=lambda r: r["va"])
    errs = [r for r in results if r["err"]]
    unimpl = collections.Counter()
    for r in results:
        for va, what in r["unimpl"]:
            unimpl[what.split(" (")[0]] += 1
    resid = [(r["va"], t) for r in results for t in r["residual"]]
    # Partition by ORIGINAL SOURCE FILE (the named tree needs units made of whole source files so the named
    # tree can include them back in the same order and compile to identical objects). Group key =
    # the PDB C13 source file of the function, else "_nosrc/<obj module>". Groups in order of their
    # lowest VA; functions inside a group by VA; units filled with whole groups up to CHUNK.
    # Group key = placement_file (feed/allocation.tsv v2: C13 file, else the compiland's source,
    # else the import library). Reader is by column name, so the v1 6-column table is refused
    # instead of being misread (format change: rule 7).
    import bisect
    alloc = {}
    with open(os.path.join(FEED, "allocation.tsv"), encoding="utf-8") as f:
        hdr = f.readline().rstrip("\n").split("\t")
        if "placement_file" not in hdr:
            sys.exit("RFG_CODEGEN REFUSED: feed/allocation.tsv has no placement_file column (rerun pdb_alloc32.py)")
        ip, iv = hdr.index("placement_file"), hdr.index("va")
        il = hdr.index("source_line") if "source_line" in hdr else None
        src_line = {}
        for line in f:
            c = line.rstrip("\n").split("\t")
            if not c[ip]:
                sys.exit(f"RFG_CODEGEN REFUSED: no placement for {c[iv]}")
            alloc[int(c[iv], 16)] = c[ip]
            if il is not None:
                src_line[int(c[iv], 16)] = int(c[il] or 0)
    pstarts = sorted(alloc)
    groups = collections.OrderedDict()
    for r in results:  # results are VA-sorted, so first appearance = lowest VA
        key = alloc.get(r["va"])
        if key is None:  # interior entries: the placement of the procedure that contains them
            key = alloc[pstarts[bisect.bisect_right(pstarts, r["va"]) - 1]]
        groups.setdefault(key, []).append(r)
    # Original source order inside each file: by the function's first C13 line; functions with no
    # line record (compiler-generated, thunks, interior entries) after them in VA order.
    for key in groups:
        groups[key].sort(key=lambda r: (0, src_line[r["va"]], r["va"]) if src_line.get(r["va"])
                         else (1, 0, r["va"]))
    units, cur = [], []
    for key, rs in groups.items():
        cur.append((key, rs))
        if sum(len(x[1]) for x in cur) >= CHUNK:
            units.append(cur)
            cur = []
    if cur:
        units.append(cur)
    files = []
    manifest = []
    for ui, unit in enumerate(units):
        fn = f"rfg_{ui:04d}.c"
        with open(os.path.join(OUT, fn), "w", encoding="utf-8", newline="\n") as w:
            w.write("/* rfg_codegen.py: pcrecomp lift32, PDB extents, units of whole source files. DO NOT EDIT. */\n")
            w.write('#define RECOMP_GENERATED_CODE\n#include "recomp_types.h"\n#include "recomp_funcs.h"\n'
                    "#include <math.h>\n#include <string.h>\n\n")
            for key, rs in unit:
                for r in rs:
                    w.write(r["code"] if not r["err"] else f"void {r['cname']}(void);  /* LIFT ERROR {r['err']} */")
                    w.write("\n\n")
                manifest.append(dict(unit=fn, group=key, vas=[f"0x{r['va']:08X}" for r in rs]))
        files.append(fn)
    json.dump(manifest, open(os.path.join(OUT, "units.json"), "w"), indent=0)
    with open(os.path.join(OUT, "recomp_funcs.h"), "w", encoding="utf-8", newline="\n") as w:
        w.write("#pragma once\n#include <stdint.h>\n\n")
        for r in results:
            w.write(f"void {r['cname']}(void);\n")
    with open(os.path.join(OUT, "recomp_dispatch.c"), "w", encoding="utf-8", newline="\n") as w:
        w.write('#include "recomp_types.h"\n#include "recomp_funcs.h"\n\n'
                "const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n")
        for r in results:
            w.write(f"    {{ 0x{r['va']:08X}u, {r['cname']} }},\n")
        w.write(f"}};\nconst uint32_t recomp_dispatch_count = {len(results)};\n")
    with open(os.path.join(OUT, "names.tsv"), "w", encoding="utf-8", newline="\n") as w:
        w.write("va\tcname\tpdb_name\n")
        for r in results:
            w.write(f"0x{r['va']:08X}\t{r['cname']}\t{r['name']}\n")
    with open(os.path.join(OUT, "residual.tsv"), "w") as w:
        w.write("from\ttarget\n")
        for a, t in resid:
            w.write(f"{a:#010x}\t{t:#010x}\n")
    with open(os.path.join(OUT, "unimpl.tsv"), "w", encoding="utf-8") as w:
        w.write("form\tsites\n")
        for k, v in unimpl.most_common():
            w.write(f"{k}\t{v}\n")
    file_hashes = {fn: hashlib.sha256(open(os.path.join(OUT, fn), "rb").read()).hexdigest()
                   for fn in files + ["recomp_funcs.h", "recomp_dispatch.c", "names.tsv", "units.json"]}
    receipt = dict(
        exe_sha256=hashlib.sha256(DATA).hexdigest(), catalog=len(funcs), lifted=len(results) - len(errs),
        lift_errors=len(errs), instructions=sum(r["n_insns"] for r in results),
        unimpl_sites=sum(unimpl.values()), unimpl_forms=dict(unimpl), residual_targets=len(resid),
        jump_tables=sum(r["tables"] for r in results), jump_tables_unguarded=sum(r["tables_unguarded"] for r in results),
        noreturn_total=len(nr), noreturn_seeds=seeds, noreturn_rounds=rounds,
        noreturn_stops=sum(r["noreturn_stops"] for r in results), decode_stops=sum(r["decode_stops"] for r in results),
        chunks=len(files), c_bytes=sum(os.path.getsize(os.path.join(OUT, f)) for f in files),
        seconds=round(time.time() - t0, 1), files_sha256=file_hashes,
        pcrecomp_head=open(os.path.join(PCRECOMP, ".git", "HEAD")).read().strip())
    json.dump(receipt, open(os.path.join(OUT, "codegen_receipt.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in receipt.items() if k != "files_sha256"}, indent=1))
    ok = (not errs) and (ALLOW_RESIDUAL or not resid) and (ALLOW_UNIMPL or not unimpl)
    for r in errs[:10]:
        print("LIFT ERROR", hex(r["va"]), r["name"], r["err"])
    print("RFG_CODEGEN DONE" if ok else "RFG_CODEGEN REFUSED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
