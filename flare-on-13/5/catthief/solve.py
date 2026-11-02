# FLARE-On 13 #5 catthief - recover exfiltrated files from capture.pcapng
# pip install dpkt
import dpkt, socket, collections, os

def tcp_streams(path):
    segs = collections.defaultdict(dict)
    for ts, buf in dpkt.pcapng.Reader(open(path, 'rb')):
        ip = dpkt.ethernet.Ethernet(buf).data
        if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP): continue
        t = ip.data
        if t.data:
            k = (socket.inet_ntoa(ip.src), t.sport, socket.inet_ntoa(ip.dst), t.dport)
            segs[k].setdefault(t.seq, (ts, bytes(t.data)))
    out = []
    for k, d in segs.items():
        items = sorted(d.items()); base = items[0][0]; b = bytearray()
        for seq, (ts, data) in items:
            off = (seq - base) & 0xffffffff; b[off:off + len(data)] = data
        out.append((items[0][1][0], k, bytes(b)))
    return sorted(out)

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; o = bytearray()
    for c in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        o.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(o)

def huff_decode(blob):
    s = ''.join(f'{x:08b}' for x in blob)
    n = int(s[:11], 2)                                   # number of code-length entries (256)
    lens = [int(s[43 + 8*i:51 + 8*i], 2) for i in range(n)]   # s[11:43] = (buggy) length field
    syms = sorted((l, i) for i, l in enumerate(lens) if l)
    codes = {}; code = 0; prev = syms[0][0]
    for idx, (l, sym) in enumerate(syms):                # canonical Huffman
        if idx: code = (code + 1) << (l - prev)
        prev = l; codes[(l, code)] = sym
    out = bytearray(); c = l = 0
    for ch in s[43 + 8*n:]:
        c = (c << 1) | (ch == '1'); l += 1
        if (l, c) in codes: out.append(codes[(l, c)]); c = l = 0
    return bytes(out)

KEY = b'i11_b3_p1und3r1n_y3r_d474'   # 25 bytes at 0x1400c9010 (+imm) XOR 0x33
streams = tcp_streams('capture.pcapng')
reqs  = [b.split(b'\r\n\r\n', 1)[1] for ts, k, b in streams if k[3] == 8080]
resps = [b.split(b'\r\n\r\n', 1)[1] for ts, k, b in streams if k[1] == 8080]
os.makedirs('out', exist_ok=True)
for i, body in enumerate(reqs):
    data = huff_decode(rc4(KEY, body))
    if i == 0:
        print('first message:', data[:5]); continue
    name = rc4(KEY, resps[i - 1]).decode()
    data = data[:data.rfind(b'\xff\xd9') + 2]            # drop padding-bit garbage
    fn = name.split(chr(92))[-1]
    open(os.path.join('out', fn), 'wb').write(data)
    print(name, '->', fn, len(data))
