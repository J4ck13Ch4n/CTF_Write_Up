import sys, struct, os, zlib
SIG=bytes([0x8b,0x12,0x02,0xb9,0x6a,0x61,0x20,0x38,0x72,0x7b,0x93,0x02,0x14,0xd7,0xa0,0x32,0x13,0xf5,0xb9,0xe6,0xef,0xae,0x33,0x18,0xee,0x3b,0x2d,0xce,0x24,0xb3,0x6a,0xae])
d=open(sys.argv[1],'rb').read(); outdir=sys.argv[2]
p=d.find(SIG); hdr=struct.unpack_from('<q',d,p-8)[0]; print('header at',hex(hdr))
o=hdr
def rstr():
    global o
    n=0;sh=0
    while True:
        b=d[o];o+=1;n|=(b&0x7f)<<sh;sh+=7
        if not b&0x80: break
    s=d[o:o+n].decode();o+=n;return s
maj,minr,cnt=struct.unpack_from('<IIi',d,o);o+=12
bid=rstr(); print('ver',maj,minr,'files',cnt,'id',bid)
if maj>=2: o+=8*4+8
for i in range(cnt):
    off,size=struct.unpack_from('<qq',d,o);o+=16
    csize=0
    if maj>=6: csize=struct.unpack_from('<q',d,o)[0];o+=8
    typ=d[o];o+=1
    path=rstr()
    data=d[off:off+(csize or size)]
    if csize: data=zlib.decompressobj(-15).decompress(data)
    fp=os.path.join(outdir,path.replace(chr(92),'/')); os.makedirs(os.path.dirname(fp) or outdir,exist_ok=True)
    open(fp,'wb').write(data)
    print(typ,size,csize,path)
