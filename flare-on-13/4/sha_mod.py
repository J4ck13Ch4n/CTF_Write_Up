import struct, pefile
pe=pefile.PE('ToxicMiner.exe'); img=pe.get_memory_mapped_image(ImageBase=0x140000000)
TAB=img[0x1bd270:0x1bd370]
K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
IV=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
M=0xffffffff
def ror(x,n): return ((x>>n)|(x<<(32-n)))&M
def compress(st,W,mod=True):
    W=list(W)+[0]*48
    for i in range(16,64):
        s0=ror(W[i-15],7)^ror(W[i-15],18)^(W[i-15]>>3); s1=ror(W[i-2],17)^ror(W[i-2],19)^(W[i-2]>>10)
        W[i]=(W[i-16]+s0+W[i-7]+s1)&M
    a,b,c,d,e,f,g,h=st
    for i in range(64):
        t1=(h+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+K[i]+W[i])&M
        t2=((ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c)))&M
        h,g,f,e,d,c,b,a=g,f,e,(d+t1)&M,c,b,a,(t1+t2)&M
    st=[(x+y)&M for x,y in zip(st,[a,b,c,d,e,f,g,h])]
    if mod:
        raw=struct.pack('<8I',*st)
        r10=st[0]; off=st[1]%28
        st[0]=TAB[r10&0xff]^struct.unpack_from('<I',raw,off)[0]^r10
    return st
def keyhash(serial,c):
    s=compress(IV,[serial,c,0x80000000]+[0]*12+[0x40])
    s=compress(IV,s+[0x80000000]+[0]*6+[0x100])
    return struct.pack('<8I',*s)
if __name__=='__main__':
    for s in (0x12345678,0xdeadbeef): print(keyhash(s,0xb501e7e).hex())
