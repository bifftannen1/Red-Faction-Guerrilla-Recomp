"""Verification for RFG PC: rerun every deterministic stage and require zero change.
  1. pe_pdb_match       MATCH + shake detected
  2. write_names        files changed: 0
  3. annotate_pdb build cnames table unchanged; organize_rfg --annotate files changed: 0, ORGANIZE_RFG DONE,
     every body strips back to its flat body; verify_pdb_annot PASS (second reader + shift control);
     pdb_headers files changed: 0, PDB_HEADERS DONE (static_asserts compile, perturbed copies fail)
  4. build_host         compiled 0, DLL sha256 == pinned in out/BUILD_SHA256 (written on first run)
  5. codegen receipt    0 errors, 0 unimpl, 0 residual
Prints VERIFY_ALL PASS only if all hold.
Usage: python -X utf8 -P -E tools/verify_all.py   (from rfg_pc_recomp)
"""
import json, os, re, subprocess, sys

PY = [sys.executable, "-X", "utf8"]
checks = []


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


rc, out = run(PY + ["-I", "probes/pe_pdb_match.py", "input/rfg.exe", "input/rfg.pdb"])
checks.append(("pe_pdb_match", rc == 0 and "VERDICT = MATCH" in out and "-> detected" in out))
rc, out = run(PY + ["-I", "tools/write_names.py", "feed", "gen", "config"])
checks.append(("write_names idempotent", rc == 0 and "files changed: 0" in out))
rc, out = run(PY + ["-P", "tools/annotate_pdb.py", "build", "."])
checks.append(("annotate_pdb cnames stable", rc == 0 and '"cnames_changed": false' in out and "ANNOTATE_PDB BUILD DONE" in out))
rc, out = run(PY + ["-P", "tools/organize_rfg.py", "gen", "gen_named", "config/source_roots.tsv", "build_units",
                    "--annotate"])
checks.append(("no _nosrc/_units in tree", not os.path.exists("gen_named/_nosrc") and not os.path.exists("gen_named/_units")))
checks.append(("organize --annotate idempotent", rc == 0 and "files changed: 0" in out and "ORGANIZE_RFG DONE" in out
               and '"bodies_strip_differ": 0' in out))
rc, out = run(PY + ["-P", "tools/verify_pdb_annot.py", ".", "gen_named", "build_units"])
checks.append(("PDB annotations re-checked by second reader + shift control", rc == 0 and "VERIFY_PDB_ANNOT PASS" in out))
rc, out = run(PY + ["-P", "tools/pdb_headers.py", ".", "include"])
checks.append(("PDB headers static_asserts + controls, idempotent", rc == 0 and "files changed: 0" in out
               and "PDB_HEADERS DONE" in out))
rc, out = run(PY + ["-P", "-E", "tools/build_host.py", "pcrecomp", "gen", "work/obj", "out", "input/rfg.exe"])
m = re.search(r"compiled (\d+) reused (\d+); rfg_host.dll \d+ bytes sha256 ([0-9a-f]{64})", out)
pin = "out/BUILD_SHA256"
if m and not os.path.exists(pin):
    open(pin, "w").write(m.group(3) + "\n")
pinned = open(pin).read().strip() if os.path.exists(pin) else None
checks.append(("build reproducible", rc == 0 and m is not None and m.group(1) == "0" and m.group(3) == pinned))
r = json.load(open("gen/codegen_receipt.json"))
checks.append(("codegen receipt", r["lift_errors"] == 0 and r["unimpl_sites"] == 0 and r["residual_targets"] == 0
               and r["lifted"] == r["catalog"]))
for name, ok in checks:
    print(("PASS " if ok else "FAIL ") + name)
ok = all(c[1] for c in checks)
print("VERIFY_ALL PASS" if ok else "VERIFY_ALL FAIL")
sys.exit(0 if ok else 1)
