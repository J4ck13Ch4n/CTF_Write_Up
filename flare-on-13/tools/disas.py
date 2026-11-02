import sys, pefile, capstone
pe=pefile.PE(sys.argv[1]); ib=pe.OPTIONAL_HEADER.ImageBase
img=pe.get_memory_mapped_image()
start=int(sys.argv[2],16); n=int(sys.argv[3]) if len(sys.argv)>3 else 200
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
import re
def s_at(va):
    o=va-ib
    if 0<=o<len(img):
        b=img[o:o+80]; m=re.match(rb'[\x20-\x7e]{4,}',b)
        if m: return repr(m.group().decode())
    return None
for i,ins in enumerate(md.disasm(img[start-ib:start-ib+n*15],start)):
    if i>=n: break
    c=''
    m=re.search(r'\[rip ([+-]) (0x[0-9a-f]+)\]',ins.op_str)
    if m:
        t=ins.address+ins.size+(int(m.group(2),16)*(1 if m.group(1)=='+' else -1))
        c='; '+hex(t)+' '+(s_at(t) or '')
    print(f'{ins.address:x}: {ins.mnemonic} {ins.op_str} {c}')
