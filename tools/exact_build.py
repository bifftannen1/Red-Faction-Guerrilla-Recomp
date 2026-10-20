"""Exact build for RFG PC: the flat units and the named-tree units must compile to identical objects.

Compiles gen/rfg_NNNN.c -> <work>/flat/rfg_recomp.N.cpp.obj and build_units/rfg_NNNN.c (the 3rd arg) ->
<work>/named/rfg_unit.N.cpp.obj with the SAME flags as build_host.py, then runs the object comparator
ds2-pc-recomp/tools/diagnostics/compare_objs_exact.py UNCHANGED (pinned by sha256 below; its
object-name pattern is why the objects are named this way). That tool compares every non-debug
section, relocation and symbol, with a negative (byte copy) and positive (flipped .text byte)
control every run, and prints EXACT PASS.
Usage: python -X utf8 -P -E exact_build.py <pcrecomp> <gen> <gen_named> <work> [--jobs J]
"""
import hashlib, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

PCRECOMP, GEN, NAMED, WORK = map(os.path.abspath, sys.argv[1:5])
JOBS = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else max(1, (os.cpu_count() or 2) - 1)
CLANG = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\Llvm\bin\clang.exe"
GATE = r"C:\Users\halox\Downloads\ds2-pc-recomp\tools\diagnostics\compare_objs_exact.py"
GATE_SHA = "a8fdfc0b297a8a774a4fb765d8c12cb511f0fdfe4d35aaad87e20e6f85c695b3"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_host import GEN_FLAGS as _GF  # noqa: E402  same flags as the shipping build

FLAGS = [f if f != os.path.join(PCRECOMP, "runtime", "recomp32") else f for f in _GF]


def main():
    t0 = time.time()
    if hashlib.sha256(open(GATE, "rb").read()).hexdigest() != GATE_SHA:
        sys.exit("EXACT REFUSED: compare_objs_exact.py does not match its pin")
    flat_dir, named_dir = os.path.join(WORK, "flat"), os.path.join(WORK, "named")
    os.makedirs(flat_dir, exist_ok=True)
    os.makedirs(named_dir, exist_ok=True)
    units = sorted(f for f in os.listdir(GEN) if f.startswith("rfg_") and f.endswith(".c"))
    jobs = []
    for u in units:
        n = int(u[4:8])
        jobs.append((os.path.join(GEN, u), os.path.join(flat_dir, f"rfg_recomp.{n}.cpp.obj")))
        jobs.append((os.path.join(NAMED, u), os.path.join(named_dir, f"rfg_unit.{n}.cpp.obj")))
    flags = ["--target=i686-pc-windows-msvc", "-O1", "-w", "-fno-strict-aliasing", "-ffp-model=strict",
             "-DRECOMP_STRICT_ICALL",
             "-I", os.path.join(PCRECOMP, "runtime", "recomp32"), "-I", GEN, "-c"]

    def cc(job):
        src, obj = job
        r = subprocess.run([CLANG] + flags + [src, "-o", obj], capture_output=True, text=True)
        return src, r.returncode, r.stderr[-1500:]

    fails = []
    with ThreadPoolExecutor(JOBS) as ex:
        for k, (src, rc, err) in enumerate(ex.map(cc, jobs)):
            if rc:
                fails.append((src, err))
            if k % 50 == 0:
                print(f"[cc] {k + 1}/{len(jobs)} ({time.time() - t0:.0f}s)", flush=True)
    if fails:
        for s, e in fails[:5]:
            print("COMPILE FAIL", s, e)
        sys.exit(f"EXACT REFUSED: {len(fails)} compiles failed")
    r = subprocess.run([sys.executable, "-X", "utf8", "-I", GATE, "--a", flat_dir, "--b", named_dir,
                        "--b-glob", "rfg_unit.*.cpp.obj", "--jobs", str(JOBS)], capture_output=True, text=True)
    print(r.stdout[-3000:], r.stderr[-2000:])
    print(f"units {len(units)}; gate rc {r.returncode}; {time.time() - t0:.0f}s")
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
