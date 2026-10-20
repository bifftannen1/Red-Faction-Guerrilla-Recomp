"""P4: compile the generated tree + native32 + host into rfg_host.dll, and write the stub EXE.

  gen/*.c            clang 19 (VS BuildTools LLVM), --target=i686-pc-windows-msvc, -O1,
                     -fno-strict-aliasing, in parallel; an object is rebuilt only when its source
                     sha256 changed (recorded in obj/sources.sha256), so a second run compiles 0
  runtime + host     cl.exe x86 (native32 needs MSVC inline asm), via vcvars32
  link               link.exe /DLL -> out/rfg_host.dll; stub -> out/rfg_recomp.exe
Refuses (exit 1) on any compile error, a missing object, or a link failure; on success prints
BUILD_OK with the object count, the DLL size and sha256, and "compiled N, reused M".
Usage: python -X utf8 -P -E build_host.py <pcrecomp> <gen_dir> <obj_dir> <out_dir> <rfg.exe> [--jobs J]
"""
import hashlib, json, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

PCRECOMP, GEN, OBJ, OUT, RFG = map(os.path.abspath, sys.argv[1:6])
JOBS = int(sys.argv[sys.argv.index("--jobs") + 1]) if "--jobs" in sys.argv else max(1, (os.cpu_count() or 2) - 1)
HERE = os.path.dirname(os.path.abspath(__file__))
HOST = os.path.join(os.path.dirname(HERE), "host")
VS = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
CLANG = VS + r"\VC\Tools\Llvm\bin\clang.exe"
VCVARS = VS + r"\VC\Auxiliary\Build\vcvars32.bat"
RT = os.path.join(PCRECOMP, "runtime")
GEN_FLAGS = ["--target=i686-pc-windows-msvc", "-O1", "-w", "-fno-strict-aliasing", "-ffp-model=strict",
             "-DRECOMP_STRICT_ICALL",   # unresolved ICALL/ITAIL -> host recomp_unresolved (rfg_host.c)
             "-I", os.path.join(RT, "recomp32"), "-I", GEN, "-c"]
# --profile fast: the performance switches from sdk patch 0012: -O2, guest memory not volatile
# (RECOMP_MEM_QUAL empty; spin-waits still reload because every back-edge makes an opaque
# RECOMP_BACKEDGE call), and the eight registers in function locals (RECOMP_LOCAL_REGS).
# Measured against the default profile before adoption (frame rate + identical game log).
PROFILE = sys.argv[sys.argv.index("--profile") + 1] if "--profile" in sys.argv else "default"
if PROFILE == "fast":
    GEN_FLAGS = ["--target=i686-pc-windows-msvc", "-O2", "-w", "-fno-strict-aliasing", "-ffp-model=strict",
                 "-DRECOMP_STRICT_ICALL", "-DRECOMP_MEM_QUAL=", "-DRECOMP_LOCAL_REGS",
                 "-I", os.path.join(RT, "recomp32"), "-I", GEN, "-c"]
elif PROFILE != "default":
    sys.exit(f"BUILD REFUSED: unknown profile {PROFILE}")


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def main():
    t0 = time.time()
    os.makedirs(OBJ, exist_ok=True)
    os.makedirs(OUT, exist_ok=True)
    srcs = sorted(f for f in os.listdir(GEN) if f.endswith(".c"))
    if not srcs:
        sys.exit("BUILD REFUSED: no generated sources")
    rec_path = os.path.join(OBJ, "sources.sha256")
    rec = json.load(open(rec_path)) if os.path.exists(rec_path) else {}
    flags_key = sha(__file__) + " ".join(GEN_FLAGS)
    todo, reused = [], 0
    hashes = {}
    for s in srcs:
        h = sha(os.path.join(GEN, s))
        hashes[s] = h
        o = os.path.join(OBJ, s[:-2] + ".obj")
        if rec.get(s) == h + flags_key and os.path.exists(o):
            reused += 1
        else:
            todo.append(s)

    def cc(s):
        o = os.path.join(OBJ, s[:-2] + ".obj")
        r = subprocess.run([CLANG] + GEN_FLAGS + [os.path.join(GEN, s), "-o", o], capture_output=True, text=True)
        return s, r.returncode, r.stderr[-2000:]

    fails = []
    with ThreadPoolExecutor(JOBS) as ex:
        for k, (s, rc, err) in enumerate(ex.map(cc, todo)):
            if rc:
                fails.append((s, err))
            else:
                rec[s] = hashes[s] + flags_key
            if k % 25 == 0:
                print(f"[cc] {k + 1}/{len(todo)} ({time.time() - t0:.0f}s)", flush=True)
    json.dump(rec, open(rec_path, "w"), indent=0)
    if fails:
        for s, e in fails[:5]:
            print("COMPILE FAIL", s, e)
        sys.exit(f"BUILD REFUSED: {len(fails)} generated files failed")
    objs = [os.path.join(OBJ, s[:-2] + ".obj") for s in srcs]
    missing = [o for o in objs if not os.path.exists(o)]
    if missing:
        sys.exit(f"BUILD REFUSED: {len(missing)} objects missing")
    rsp = os.path.join(OBJ, "link.rsp")
    with open(rsp, "w") as w:
        for o in objs:
            w.write(f'"{o}"\n')
    dll = os.path.join(OUT, "rfg_host.dll")
    cmd = (f'call "{VCVARS}" >nul && cl /nologo /c /O1 /MT /Brepro /I"{RT}\\native32" /I"{RT}\\recomp32" '
           f'"{HOST}\\rfg_host.c" "{RT}\\native32\\native32.c" "{RT}\\recomp32\\image_loader.c" '
           f'"{RT}\\recomp32\\recomp_trace.c" /Fo"{OBJ}\\\\" && '
           f'link /nologo /DLL /Brepro /OUT:"{dll}" /BASE:0x40000000 /LARGEADDRESSAWARE /SAFESEH:NO '
           f'"{OBJ}\\rfg_host.obj" "{OBJ}\\native32.obj" "{OBJ}\\image_loader.obj" "{OBJ}\\recomp_trace.obj" '
           f'@"{rsp}" kernel32.lib user32.lib synchronization.lib')
    bat = os.path.join(OBJ, "host_link.cmd")
    open(bat, "w").write("@echo off\r\n" + cmd + "\r\n")
    r = subprocess.run(["cmd", "/c", bat], capture_output=True, text=True)
    open(os.path.join(OBJ, "host_link.log"), "w").write(r.stdout + r.stderr)
    if r.returncode or not os.path.exists(dll):
        print((r.stdout + r.stderr)[-4000:])
        sys.exit("BUILD REFUSED: host compile/link failed")
    stub = os.path.join(OUT, "rfg_recomp.exe")
    r2 = subprocess.run([sys.executable, "-X", "utf8", "-I", os.path.join(HOST, "make_stub_exe.py"), RFG, stub,
                         "rfg_host.dll", "rfg_main"], capture_output=True, text=True)
    if r2.returncode:
        print(r2.stdout + r2.stderr)
        sys.exit("BUILD REFUSED: stub")
    print(f"BUILD_OK objects {len(objs)} compiled {len(todo)} reused {reused}; rfg_host.dll "
          f"{os.path.getsize(dll)} bytes sha256 {sha(dll)}; stub {sha(stub)[:16]}; {time.time() - t0:.0f}s")


if __name__ == "__main__":
    main()
