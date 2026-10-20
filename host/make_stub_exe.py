"""Write a stub PE32 EXE that holds a guest image's whole range from process creation.

Layout (base = guest ImageBase, fixed, no relocations):
  headers                      RVA 0
  .guest  uninitialized RW     RVA 0x1000 .. guest SizeOfImage   (the reservation)
  .stub   code + imports       RVA = guest SizeOfImage (page aligned)
The stub's entry does:  h = LoadLibraryA("<host dll>"); f = GetProcAddress(h, "<export>");
                        ExitProcess(f ? f() : 0x7F)
The host DLL then copies the guest into the reservation (image_loader.c, stub path).

Usage: python -X utf8 -I make_stub_exe.py <guest.exe> <out.exe> [host.dll] [export] [--gui]
Verifies its own output: re-parses the headers, checks the reservation covers the guest span,
and disassembles the entry with capstone if available. Prints STUB_EXE DONE.
"""
import struct, sys

args = [a for a in sys.argv[1:] if not a.startswith("--")]
guest, out = args[0], args[1]
dll = (args[2] if len(args) > 2 else "rfg_host.dll").encode() + b"\0"
export = (args[3] if len(args) > 3 else "rfg_main").encode() + b"\0"
subsystem = None  # set from the guest below unless --console

g = open(guest, "rb").read()
lf = struct.unpack_from("<I", g, 0x3C)[0]
assert g[lf:lf + 4] == b"PE\0\0"
opt = lf + 24
BASE = struct.unpack_from("<I", g, opt + 28)[0]
G_SIZE = struct.unpack_from("<I", g, opt + 56)[0]
# Flags the PROCESS inherits from its EXE must be the guest's: LARGE_ADDRESS_AWARE (0x20) decides
# whether the process gets 4 GB under WOW64 (RFG reserves 2,346,365,000 bytes at startup and shows
# "Could not allocate" without it), and the guest's subsystem decides console vs GUI. The stub's
# own facts (relocs stripped, executable, 32-bit) are fixed; ASLR stays off (the image is fixed).
G_CHAR = struct.unpack_from("<H", g, lf + 22)[0]
G_SUBSYS = struct.unpack_from("<H", g, opt + 68)[0]
G_DLLCHAR = struct.unpack_from("<H", g, opt + 70)[0]
STUB_CHAR = 0x0103 | (G_CHAR & 0x0020)                 # RELOCS_STRIPPED|EXECUTABLE|32BIT + guest LAA
STUB_DLLCHAR = (G_DLLCHAR & ~0x0040) | 0x0100          # guest flags minus DYNAMIC_BASE, plus NX_COMPAT
subsystem = 3 if "--console" in sys.argv else G_SUBSYS
SA, FA = 0x1000, 0x200
STUB_RVA = (G_SIZE + SA - 1) & ~(SA - 1)

# ---- .stub contents (offsets within the section)
imports = [b"LoadLibraryA", b"GetProcAddress", b"ExitProcess"]
sec = bytearray(0x400)
o_code = 0x000
o_dll = 0x080
o_exp = 0x0A0
o_kname = 0x0C0
o_hint = 0x0D0
o_ilt = 0x140
o_iat = 0x160
o_idesc = 0x180
va = lambda off: BASE + STUB_RVA + off
rva = lambda off: STUB_RVA + off

sec[o_dll:o_dll + len(dll)] = dll
sec[o_exp:o_exp + len(export)] = export
sec[o_kname:o_kname + 13] = b"KERNEL32.dll\0"
hint_rvas = []
p = o_hint
for name in imports:
    hint_rvas.append(rva(p))
    ent = b"\0\0" + name + b"\0"
    if len(ent) % 2:
        ent += b"\0"
    sec[p:p + len(ent)] = ent
    p += len(ent)
assert p <= o_ilt
for i, h in enumerate(hint_rvas):
    struct.pack_into("<I", sec, o_ilt + 4 * i, h)
    struct.pack_into("<I", sec, o_iat + 4 * i, h)
struct.pack_into("<IIIII", sec, o_idesc, rva(o_ilt), 0, 0, rva(o_kname), rva(o_iat))
IAT_LL, IAT_GPA, IAT_EXIT = va(o_iat), va(o_iat + 4), va(o_iat + 8)

code = bytearray()
code += b"\x68" + struct.pack("<I", va(o_dll))            # push dll
code += b"\xFF\x15" + struct.pack("<I", IAT_LL)           # call [LoadLibraryA]
code += b"\x85\xC0"                                       # test eax, eax
jz1 = len(code); code += b"\x74\x00"                      # jz fail
code += b"\x68" + struct.pack("<I", va(o_exp))            # push export
code += b"\x50"                                           # push eax
code += b"\xFF\x15" + struct.pack("<I", IAT_GPA)          # call [GetProcAddress]
code += b"\x85\xC0"                                       # test eax, eax
jz2 = len(code); code += b"\x74\x00"                      # jz fail
code += b"\xFF\xD0"                                       # call eax
code += b"\x50"                                           # push eax
code += b"\xFF\x15" + struct.pack("<I", IAT_EXIT)         # call [ExitProcess]
fail = len(code)
code += b"\x6A\x7F"                                       # push 0x7F
code += b"\xFF\x15" + struct.pack("<I", IAT_EXIT)         # call [ExitProcess]
code[jz1 + 1] = fail - (jz1 + 2)
code[jz2 + 1] = fail - (jz2 + 2)
assert len(code) <= o_dll
sec[o_code:o_code + len(code)] = code

# ---- headers
nsec = 2
hdr = bytearray(0x400)
hdr[0:2] = b"MZ"
struct.pack_into("<I", hdr, 0x3C, 0x80)
nt = 0x80
hdr[nt:nt + 4] = b"PE\0\0"
struct.pack_into("<HHIIIHH", hdr, nt + 4, 0x14C, nsec, 0, 0, 0, 0xE0, STUB_CHAR)
o = nt + 24
size_image = STUB_RVA + SA
struct.pack_into("<HBBIIIIIII", hdr, o, 0x10B, 14, 0, 0x400, 0, (G_SIZE - SA), rva(o_code), rva(0), SA, BASE)
struct.pack_into("<IIHHHHHHIIIIHH", hdr, o + 32, SA, FA, 6, 0, 0, 0, 6, 0, 0, size_image, 0x400, 0,
                 subsystem, STUB_DLLCHAR)
struct.pack_into("<IIIIII", hdr, o + 72, 0x40000, 0x1000, 0x100000, 0x1000, 0, 16)
dd = o + 96
struct.pack_into("<II", hdr, dd + 8 * 1, rva(o_idesc), 40)    # import directory
struct.pack_into("<II", hdr, dd + 8 * 12, rva(o_iat), 16)     # IAT
sh = o + 0xE0
struct.pack_into("<8sIIIIIIHHI", hdr, sh, b".guest", G_SIZE - SA, SA, 0, 0, 0, 0, 0, 0, 0xC0000080)
struct.pack_into("<8sIIIIIIHHI", hdr, sh + 40, b".stub", 0x400, STUB_RVA, 0x400, 0x400, 0, 0, 0, 0, 0xE0000060)
img = bytes(hdr) + bytes(sec)
open(out, "wb").write(img)

# ---- verify
r = open(out, "rb").read()
lf2 = struct.unpack_from("<I", r, 0x3C)[0]
base2 = struct.unpack_from("<I", r, lf2 + 24 + 28)[0]
s0 = struct.unpack_from("<8sII", r, lf2 + 24 + 0xE0)
s1 = struct.unpack_from("<8sII", r, lf2 + 24 + 0xE0 + 40)
ch2 = struct.unpack_from("<H", r, lf2 + 22)[0]
ok = (ch2 & 0x20) == (G_CHAR & 0x20) and base2 == BASE and s0[2] == SA and SA + s0[1] >= G_SIZE and s1[2] >= G_SIZE
print(f"characteristics {STUB_CHAR:#06x} (guest {G_CHAR:#06x}) dllchar {STUB_DLLCHAR:#06x}; guest base {BASE:#x} size {G_SIZE:#x}; stub base {base2:#x}; .guest RVA {s0[2]:#x} size {s0[1]:#x}; "
      f".stub RVA {s1[2]:#x}; file {len(r)} bytes; subsystem {subsystem}")
try:
    import site
    sys.path.append(site.getusersitepackages())
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    for i in Cs(CS_ARCH_X86, CS_MODE_32).disasm(bytes(code), va(o_code)):
        print(f"  {i.address:#x}  {i.mnemonic} {i.op_str}")
except ImportError:
    print("  (capstone not available: entry not disassembled)")
print("STUB_EXE DONE" if ok else "STUB_EXE REFUSED")
sys.exit(0 if ok else 1)
