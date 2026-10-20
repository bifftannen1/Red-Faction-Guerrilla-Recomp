"""One-command build of the published repository (Windows, x86 target).

  python tools/build.py --exe "<GOG install>\\rfg.exe" [--profile default|fast] [--jobs N]

1. Checks rfg.exe against the pinned sha256 (GOG 1.0_fix (79624)); refuses anything else.
2. Gets pcrecomp: thirdparty/pcrecomp = upstream at sdk/PCRECOMP_BASE.txt + sdk/patches (git am).
3. Compiles units/*.c (which #include the src/ tree) and units/recomp_dispatch.c with clang (VS 2022 Build Tools LLVM,
   --target=i686-pc-windows-msvc), the native32 runtime + host with MSVC x86 cl, links
   out/rfg_host.dll (/Brepro) and writes out/rfg_recomp.exe (stub).
Prints BUILD_OK with the DLL sha256. Copy rfg_recomp.exe + rfg_host.dll next to rfg.exe and run
rfg_recomp.exe (see README). Needs: Python 3.10+, git, VS 2022 Build Tools with C++ and Clang.
"""
import argparse, glob, hashlib, os, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RFG_SHA = "7a82d2d0f425af5e75d8ffbce12fac53eb5ca9cd812731ccf5a29697e906af0e"
VS = r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
CLANG = VS + r"\VC\Tools\Llvm\bin\clang.exe"
VCVARS32 = VS + r"\VC\Auxiliary\Build\vcvars32.bat"


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def run(cmd, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        print(r.stdout[-3000:], r.stderr[-3000:])
        sys.exit(f"BUILD REFUSED: {cmd[0] if isinstance(cmd, list) else cmd} rc {r.returncode}")
    return r


def get_pcrecomp():
    dst = os.path.join(ROOT, "thirdparty", "pcrecomp")
    base = open(os.path.join(ROOT, "sdk", "PCRECOMP_BASE.txt")).read().split("base")[1].split()[0]
    patches = sorted(glob.glob(os.path.join(ROOT, "sdk", "patches", "*.patch")))
    stamp = os.path.join(dst, ".rfg_patched")
    want = base + "\n" + "\n".join(sha(p) for p in patches)
    if os.path.exists(stamp) and open(stamp).read() == want:
        return dst
    if not os.path.isdir(os.path.join(dst, ".git")):
        run(["git", "clone", "-q", "https://github.com/sp00nznet/pcrecomp.git", dst])
    run(["git", "-C", dst, "checkout", "-q", "-f", base])
    run(["git", "-C", dst, "-c", "user.name=rfg-build", "-c", "user.email=rfg-build@localhost", "am", "-q", "--keep-cr"] + patches)
    open(stamp, "w").write(want)
    return dst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--profile", default="default", choices=["default", "fast"])
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    a = ap.parse_args()
    t0 = time.time()
    # The game's own source tree is deep (longest repo path 156 chars): clang on Windows stops at
    # MAX_PATH (260) for includes, so the clone location must leave room. Refuse early, clearly.
    longest = max(len(os.path.join(dp, f)) for dp, _, fs in os.walk(os.path.join(ROOT, "src")) for f in fs)
    if longest >= 259:
        sys.exit(f"BUILD REFUSED: the deepest source path is {longest} characters here (Windows limit 260). "
                 f"Clone to a shorter folder, e.g. C:\\src\\rfg-recomp ({len(ROOT)} characters used by {ROOT}).")
    if sha(a.exe) != RFG_SHA:
        sys.exit(f"BUILD REFUSED: {a.exe} is not GOG rfg.exe 1.0_fix (79624) (sha256 {RFG_SHA})")
    pc = get_pcrecomp()
    rt = os.path.join(pc, "runtime")
    src = os.path.join(ROOT, "src")
    obj = os.path.join(ROOT, "build", "obj_" + a.profile)
    out = os.path.join(ROOT, "out")
    os.makedirs(obj, exist_ok=True)
    os.makedirs(out, exist_ok=True)
    flags = ["--target=i686-pc-windows-msvc", "-O1", "-w", "-fno-strict-aliasing", "-ffp-model=strict",
             "-DRECOMP_STRICT_ICALL"]
    if a.profile == "fast":
        flags = ["--target=i686-pc-windows-msvc", "-O2", "-w", "-fno-strict-aliasing", "-ffp-model=strict",
                 "-DRECOMP_STRICT_ICALL", "-DRECOMP_MEM_QUAL=", "-DRECOMP_LOCAL_REGS"]
    flags += ["-I", os.path.join(rt, "recomp32"), "-I", os.path.join(ROOT, "units"), "-c"]
    udir = os.path.join(ROOT, "units")
    units = sorted(glob.glob(os.path.join(udir, "rfg_*.c"))) + [os.path.join(udir, "recomp_dispatch.c")]

    def cc(u):
        o = os.path.join(obj, os.path.basename(u)[:-2] + ".obj")
        r = subprocess.run([CLANG] + flags + [u, "-o", o], capture_output=True, text=True)
        return u, r.returncode, r.stderr[-1500:], o

    objs, fails = [], []
    with ThreadPoolExecutor(a.jobs) as ex:
        for k, (u, rc, err, o) in enumerate(ex.map(cc, units)):
            (fails.append((u, err)) if rc else objs.append(o))
            if k % 25 == 0:
                print(f"[cc] {k + 1}/{len(units)} ({time.time() - t0:.0f}s)", flush=True)
    if fails:
        for u, e in fails[:3]:
            print("COMPILE FAIL", u, e)
        sys.exit(f"BUILD REFUSED: {len(fails)} units failed")
    rsp = os.path.join(obj, "link.rsp")
    open(rsp, "w").write("".join(f'"{o}"\n' for o in objs))
    host = os.path.join(ROOT, "host")
    dll = os.path.join(out, "rfg_host.dll")
    bat = os.path.join(obj, "host_link.cmd")
    open(bat, "w").write("@echo off\r\n" + (
        f'call "{VCVARS32}" >nul && cl /nologo /c /O1 /MT /Brepro /I"{rt}\\native32" /I"{rt}\\recomp32" '
        f'"{host}\\rfg_host.c" "{rt}\\native32\\native32.c" "{rt}\\recomp32\\image_loader.c" "{rt}\\recomp32\\recomp_trace.c" '
        f'/Fo"{obj}\\\\" && link /nologo /DLL /Brepro /OUT:"{dll}" /BASE:0x40000000 /LARGEADDRESSAWARE /SAFESEH:NO '
        f'"{obj}\\rfg_host.obj" "{obj}\\native32.obj" "{obj}\\image_loader.obj" "{obj}\\recomp_trace.obj" @"{rsp}" '
        f'kernel32.lib user32.lib synchronization.lib\r\n'))
    run(["cmd", "/c", bat])
    run([sys.executable, "-X", "utf8", "-I", os.path.join(host, "make_stub_exe.py"), a.exe,
         os.path.join(out, "rfg_recomp.exe"), "rfg_host.dll", "rfg_main"])
    print(f"BUILD_OK profile {a.profile} units {len(objs)} rfg_host.dll sha256 {sha(dll)} ({time.time() - t0:.0f}s)")


if __name__ == "__main__":
    main()
