import pefile, struct, hashlib
from unicorn import *
from unicorn.x86_const import *
pe=pefile.PE('ToxicMiner.exe'); img=pe.get_memory_mapped_image(ImageBase=0x140000000)
BASE=0x140000000
mu=Uc(UC_ARCH_X86,UC_MODE_64)
mu.mem_map(BASE,(len(img)+0xfff)&~0xfff); mu.mem_write(BASE,img)
mu.mem_map(0x10000000,0x100000)
def run(serial,c):
    rsp=0x10080000
    out=0x10010000
    mu.mem_write(rsp,struct.pack('<Q',0xdeadbeef))
    mu.reg_write(UC_X86_REG_RSP,rsp); mu.reg_write(UC_X86_REG_RCX,serial); mu.reg_write(UC_X86_REG_RDX,c); mu.reg_write(UC_X86_REG_R8,out)
    try: mu.emu_start(0x140134ca0,0xdeadbeef)
    except UcError as e: print(e, hex(mu.reg_read(UC_X86_REG_RIP)))
    return bytes(mu.mem_read(out,32))
def py(serial,c):
    h=hashlib.sha256(hashlib.sha256(struct.pack('>II',serial,c)).digest()).digest()
    return b''.join(h[i:i+4][::-1] for i in range(0,32,4))
for s in (0x12345678,0xdeadbeef):
    print(run(s,0xb501e7e).hex()); print(py(s,0xb501e7e).hex())
