# usage: xref.py <pe> <target_va_hex> [range]
import sys, pefile, re
pe=pefile.PE(sys.argv[1],fast_load=True); ib=pe.OPTIONAL_HEADER.ImageBase
t=int(sys.argv[2],16); rng=int(sys.argv[3]) if len(sys.argv)>3 else 0
for s in pe.sections:
    if not s.Characteristics & 0x20000000: continue
    code=s.get_data(); base=ib+s.VirtualAddress
    # any rip-relative disp32 at positions: scan all offsets
    for off in range(len(code)-4):
        disp=int.from_bytes(code[off:off+4],'little',signed=True)
        # candidate instruction end = off+4 (+imm possibly) ; check common: end = off+4
        for extra in (0,1,4):
            tgt=base+off+4+extra+disp
            if t<=tgt<=t+rng:
                print(hex(base+off), 'extra',extra, hex(tgt))
