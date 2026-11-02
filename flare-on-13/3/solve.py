"""FLARE-On 13 #3 - FlareOn13.doc (polyglot) - trích 6 mảnh và giải flag."""
import hashlib, re, struct, zlib

D = open('flareon13.doc', 'rb').read()


def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for c in data:
        i = (i + 1) & 0xff; j = (j + S[i]) & 0xff; S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 0xff])
    return bytes(out)


# ---- 1. COM / EICAR: chương trình DOS tự sửa rồi in chuỗi "$"-terminated ----
com = bytearray(D[:0x100])
# emulate phần self-modify: bx = 0x2020^0x2160 = 0x140 ; xor [bx+0x20..0x24] với al
bx = 0x2020 ^ 0x2160
for k, x in enumerate([0x6023, 0x6025, 0x6022, 0x6033, 0x6037]):
    com[bx + 0x20 + k - 0x100] ^= (0x4020 ^ x) & 0xff
s = com.index(b'-STANDARD') - 5
frag_com = bytes(com[s:com.index(b'$', s)]).decode()

# ---- 2+3. PDF (RC4-40, user password rỗng): text EBCDIC + ảnh JBIG2 ----
PAD = bytes.fromhex('28BF4E5E4E758A4164004E56FFFA01082E2E00B6D0683E802F0CA9FE6453697A')
enc = re.search(rb'/O <([0-9a-f]+)> /U <([0-9a-f]+)> /P (-?\d+)', D)
O, P = bytes.fromhex(enc.group(1).decode()), int(enc.group(3))
ID = bytes.fromhex(re.search(rb'/ID \[<([0-9a-f]+)>', D).group(1).decode())
fkey = hashlib.md5(PAD + O + struct.pack('<i', P) + ID).digest()[:5]
okey = lambda n: hashlib.md5(fkey + struct.pack('<I', n)[:3] + b'\0\0').digest()[:10]
m = re.search(rb'5 0 obj\n<< /Length (\d+) >>\nstream\n', D)
content = rc4(okey(5), D[m.end():m.end() + int(m.group(1))])
hexstr = re.search(rb'<([0-9a-f]+)> Tj', content).group(1)
frag_ebcdic = bytes.fromhex(hexstr.decode()).decode('cp500')
frag_jbig2 = 'jbig2_fax_geometry'   # đọc từ ảnh JBIG2 808x48 (obj 8), render bằng PyMuPDF

# ---- 4. ZIP: ZipCrypto("infected") + Reduce factor 1 ----
z = D.index(b'PK\x03\x04')
_, _, flag_, meth, _, _, crc, csz, usz, fnl, exl = struct.unpack_from('<IHHHHHIIIHH', D, z)
data = D[z + 30 + fnl + exl: z + 30 + fnl + exl + csz]
T = [0] * 256
for i in range(256):
    c = i
    for _ in range(8): c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    T[i] = c
cb = lambda c, b: T[(c ^ b) & 0xff] ^ (c >> 8)
k = [0x12345678, 0x23456789, 0x34567890]
def upd(c):
    k[0] = cb(k[0], c); k[1] = ((k[1] + (k[0] & 0xff)) * 134775813 + 1) & 0xffffffff; k[2] = cb(k[2], k[1] >> 24)
for c in b'infected': upd(c)
dec = bytearray()
for c in data:
    t = (k[2] | 2) & 0xffff; p = c ^ (((t * (t ^ 1)) >> 8) & 0xff); upd(p); dec.append(p)
dec = bytes(dec[12:])
bp = 0
def bits(n):
    global bp
    v = 0
    for q in range(n):
        v |= ((dec[bp >> 3] >> (bp & 7)) & 1) << q; bp += 1
    return v
FS = [None] * 256
for j in range(255, -1, -1):
    FS[j] = [bits(8) for _ in range(bits(6))]
out = bytearray(); last = st = V = Ln = 0
while len(out) < usz:
    if not FS[last]: c = bits(8)
    elif bits(1): c = bits(8)
    else: c = FS[last][bits(max(1, (len(FS[last]) - 1).bit_length()))]
    last = c
    if st == 0:
        if c != 144: out.append(c)
        else: st = 1
    elif st == 1:
        if c: V = c; Ln = V & 0x7f; st = 2 if Ln == 0x7f else 3
        else: out.append(144); st = 0
    elif st == 2: Ln += c; st = 3
    else:
        off = ((V >> 7) << 8) + c + 1
        for _ in range(Ln + 3): out.append(out[-off])
        st = 0
assert zlib.crc32(out) == crc
frag_zip = out.decode()

# ---- 5. Raw CD (2352 B/sector, Mode 1) -> UDF: LVInfo1 của Implementation Use VD (sector 21) ----
iso = b''.join(D[l * 2352 + 16: l * 2352 + 16 + 2048] for l in range(len(D) // 2352))
iuvd = iso[21 * 2048: 22 * 2048]
assert struct.unpack_from('<H', iuvd)[0] == 4                # tag 4 = Implementation Use VD
lvinfo1 = iuvd[244:280]                                      # dstring[36], byte cuối = độ dài
frag_udf = lvinfo1[1:lvinfo1[35]].decode()

# ---- 6. Mach-O slice arm64 (click_me): chuỗi in ra mỗi frame ----
frag_macho = 'Ød1n_373rn4l_fl4r3'   # emulate 0x1000006b4..0x100000aa4 bằng Unicorn

frags = [frag_com, frag_ebcdic, frag_jbig2, frag_udf, frag_zip, frag_macho]
for f in frags: print('fragment:', f)

# ---- Checker (slice Crystal): 6 MD5 + ciphertext được mã hóa dạng nibble 0x8X ----
fat = iso[iso.index(b'\xca\xfe\xba\xbe'):]        # click_me nằm liền mạch trong user-data của CD
off = struct.unpack_from('>I', fat, 8 + 20 + 8)[0]
blob = fat[off + 0x35e30: off + 0x35f40]
hx = ''.join('%x' % (b & 0xf) for b in blob)
for f in frags:
    assert hashlib.md5(f.encode()).hexdigest() in hx[:192], f
key = bytearray(32)
for f in frags:
    for i, b in enumerate(hashlib.sha256(f.encode()).digest()): key[i] ^= b
print('FLAG:', rc4(bytes(key), bytes.fromhex(hx[192:])).decode())
