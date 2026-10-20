"""Prove a PE and a PDB belong together: RSDS (GUID, age, path) in the PE debug directory
vs the PDB info stream (stream 1) GUID/age and DBI stream age.
Usage: python -I pe_pdb_match.py <pe> <pdb>
Exit 0 and print MATCH only when GUIDs equal and PDB age >= PE age (PDB age equal is exact).
Negative control: --shake flips one GUID byte in memory and must report MISMATCH.
"""
import hashlib, struct, sys, uuid


def pe_rsds(path):
    b = open(path, "rb").read()
    e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
    assert b[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not PE"
    coff = e_lfanew + 4
    machine, nsec, ts, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", b, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", b, opt)[0]
    dd = opt + (96 if magic == 0x10B else 112)
    image_base = struct.unpack_from("<I" if magic == 0x10B else "<Q", b, opt + (28 if magic == 0x10B else 24))[0]
    dbg_rva, dbg_size = struct.unpack_from("<II", b, dd + 6 * 8)
    secs = []
    so = opt + optsz
    for i in range(nsec):
        name, vsz, va, rsz, rptr = struct.unpack_from("<8sIIII", b, so + 40 * i)
        secs.append((name.rstrip(b"\0").decode(), va, vsz, rptr, rsz))

    def rva2off(rva):
        for n, va, vsz, rptr, rsz in secs:
            if va <= rva < va + max(vsz, rsz):
                return rptr + rva - va
        raise ValueError(hex(rva))

    out = []
    off = rva2off(dbg_rva)
    for i in range(dbg_size // 28):
        ch, tds, maj, mn, typ, sz, rva, ptr = struct.unpack_from("<IIHHIIII", b, off + 28 * i)
        if typ == 2 and b[ptr:ptr + 4] == b"RSDS":
            g = uuid.UUID(bytes_le=b[ptr + 4:ptr + 20])
            age = struct.unpack_from("<I", b, ptr + 20)[0]
            p = b[ptr + 24:ptr + sz].split(b"\0")[0].decode("latin-1")
            out.append((g, age, p))
    return dict(machine=hex(machine), timestamp=ts, image_base=hex(image_base),
                sections=[s[0] for s in secs], rsds=out, sha256=hashlib.sha256(b).hexdigest(), size=len(b))


def pdb_info(path):
    f = open(path, "rb")
    sb = f.read(56)
    assert sb[:24] == b"Microsoft C/C++ MSF 7.00", "not MSF7"
    bs, fpm, nblocks, dir_bytes, _, map_addr = struct.unpack_from("<IIIIII", sb, 32)
    ndirblocks = -(-dir_bytes // bs)
    f.seek(map_addr * bs)
    dir_block_ids = struct.unpack("<%dI" % ndirblocks, f.read(4 * ndirblocks))
    d = b""
    for bi in dir_block_ids:
        f.seek(bi * bs)
        d += f.read(bs)
    d = d[:dir_bytes]
    nstreams = struct.unpack_from("<I", d, 0)[0]
    sizes = struct.unpack_from("<%dI" % nstreams, d, 4)
    pos = 4 + 4 * nstreams
    blocks = []
    for s in sizes:
        n = 0 if s == 0xFFFFFFFF else -(-s // bs)
        blocks.append(struct.unpack_from("<%dI" % n, d, pos))
        pos += 4 * n

    def stream(i):
        buf = b""
        for bi in blocks[i]:
            f.seek(bi * bs)
            buf += f.read(bs)
        return buf[:sizes[i]]

    s1 = stream(1)
    ver, sig, age = struct.unpack_from("<III", s1, 0)
    g = uuid.UUID(bytes_le=s1[12:28])
    s3 = stream(3)
    dbi_age = struct.unpack_from("<I", s3, 8)[0] if len(s3) >= 12 else None
    f.seek(0, 2)
    return dict(block_size=bs, nstreams=nstreams, version=ver, guid=g, age=age, dbi_age=dbi_age,
                file_size=f.tell(), sha256=hashlib.sha256(open(path, "rb").read()).hexdigest())


def verdict(pe_g, pe_age, pdb_g, pdb_age):
    return "MATCH" if pe_g == pdb_g and pdb_age >= pe_age else "MISMATCH"


pe = pe_rsds(sys.argv[1])
pdb = pdb_info(sys.argv[2])
for k, v in pe.items():
    print(f"PE.{k} = {v}")
for k, v in pdb.items():
    print(f"PDB.{k} = {v}")
assert pe["rsds"], "PE has no RSDS record"
g, age, path = pe["rsds"][0]
v = verdict(g, age, pdb["guid"], pdb["age"])
exact = v == "MATCH" and pdb["age"] == age
print(f"VERDICT = {v} (exact_age={exact})")
# negative control: perturb one GUID byte; must not match
bad = uuid.UUID(bytes_le=bytes([g.bytes_le[0] ^ 0xFF]) + g.bytes_le[1:])
shake = verdict(bad, age, pdb["guid"], pdb["age"])
print(f"SHAKE (flipped GUID byte) = {shake} -> {'detected' if shake == 'MISMATCH' else 'NOT DETECTED'}")
sys.exit(0 if v == "MATCH" and shake == "MISMATCH" else 1)
