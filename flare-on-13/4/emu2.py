import struct
from emu_check import mu, BASE
from unicorn.x86_const import *
from sha_mod import compress, IV
def emu_tr(st,W):
    rsp=0x10080000; stp=0x10010000; wp=0x10020000
    mu.mem_write(rsp,struct.pack('<Q',0xdeadbeef))
    mu.mem_write(stp,struct.pack('<8I',*st)); mu.mem_write(wp,struct.pack('<16I',*W))
    mu.reg_write(UC_X86_REG_RSP,rsp); mu.reg_write(UC_X86_REG_RCX,stp); mu.reg_write(UC_X86_REG_RDX,wp); mu.reg_write(UC_X86_REG_R8,0)
    mu.emu_start(0x140135240,0xdeadbeef)
    return list(struct.unpack('<8I',mu.mem_read(stp,32)))
W=[0x12345678,0xb501e7e,0x80000000]+[0]*12+[0x40]
print([hex(x) for x in emu_tr(IV,W)])
print([hex(x) for x in compress(IV,W,False)])
print([hex(x) for x in compress(IV,W,True)])
