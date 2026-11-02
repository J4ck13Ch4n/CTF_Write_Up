import struct

# --- 1. Trích xuất từ GhostStream.wim (uncompressed) ---
wim = open('GhostStream.wim', 'rb').read()
exe = wim[208:208 + 35328]                 # GhostStream.exe
main_stream = wim[35536:35536 + 316]       # PolyjuicePotion.txt (unnamed stream)
ads = wim[35852:35852 + 18]                # PolyjuicePotion.txt:LordVoldemort
print('ADS LordVoldemort =', ads)

# --- 2. Parent: WndProc biến đổi key khi uptime > 10080 phút ---
WND = bytes([0x8b, 0x8f, 0x92, 0x85, 0x88, 0x96, 0x98, 0x9b,
             0x94, 0x8b, 0x95, 0xe6, 0xed, 0xf0, 0xe7])
r11 = 0x01 ^ 0x83                          # WM_CREATE ^ WM_NCCALCSIZE
buf = bytearray(b ^ r11 for b in ads)
for i in range(15):
    buf[i] ^= WND[i]
key = bytes(buf).split(b'\0')[0]           # WriteFile(pipe, buf, strlen(buf))
print('pipe key =', key)

# --- 3. Partner: chuỗi XOR được giải bởi strlen bị hook ---
xk = bytearray(b'Bxs]bv`^u)TpcnolVjN')
dl = 1
for i in range(len(xk)):
    xk[i] = ((xk[i] + dl) & 0xff) ^ 0x13
    dl += 1
print('xor string =', bytes(xk))

# --- 4. Partner: RC4 biến thể ---
CT = struct.pack('<9IH', 0x35875c96, 0x8b397ad7, 0x286d0475, 0xc85856bb, 0xe1daee35,
                 0x37a956a4, 0xf9561581, 0x0d340a27, 0x262c82ee, 0xf8a5)
STEP = len(b'Wingardium Leviosa')          # 18 = 0x12

S = list(range(256)); j = 0
for i in range(256):
    j = (j + key[i % len(key)] + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
i = j = 0; flag = bytearray()
for k, c in enumerate(CT):
    i = (i + STEP) & 0xff
    j = (j + S[i]) & 0xff
    S[i], S[j] = S[j], S[i]
    flag.append(S[(S[i] + S[j]) & 0xff] ^ xk[k % len(xk)] ^ ((c + STEP) & 0xff))
print('FLAG =', flag.decode())
