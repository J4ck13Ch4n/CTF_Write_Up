#!/usr/bin/env python3
"""FlareCalc - node 4485: emulated XTEA-decrypt of entry 9990's 40 ciphertext
bytes, keyed with the 32-byte state buffer the 32-step walk produced.

Calling convention (reverse-engineered from the 384-byte stub):
    rcx = output buffer (40 bytes, strlen result returned in eax)
    rdx = ciphertext pointer (read big-endian dwords, 8 bytes per block,
          five blocks)
    r8  = 32-byte key pointer; the stub first folds
          k[i] = key32[16+4i] ^ key32[4i]  (i = 0..3)  into rsp[0..16)
The stub is plain arithmetic (no stall loop), so no patching is needed.
"""
import pickle
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
from unicorn.x86_const import (UC_X86_REG_CL, UC_X86_REG_RCX, UC_X86_REG_RDX,
                               UC_X86_REG_R8, UC_X86_REG_RSP, UC_X86_REG_RAX,
                               UC_X86_REG_RBX, UC_X86_REG_RSI, UC_X86_REG_RDI,
                               UC_X86_REG_RBP, UC_X86_REG_R9, UC_X86_REG_R10,
                               UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
                               UC_X86_REG_R14, UC_X86_REG_R15)

D = pickle.load(open('/tmp/opencode/code_cont.pkl', 'rb'))['code']
SOL = pickle.load(open('/tmp/opencode/walk_solutions.pkl', 'rb'))['sol']
W = {'walk': ''.join(SOL[0][0]), 'key': SOL[0][1]}

CODE_BASE = 0x100000
STACK_BASE = 0x200000
KEY_BASE = 0x300000
IN_BASE = 0x301000
OUT_BASE = 0x302000
SENTINEL = 0x400000


def main():
    key = W['key']
    data = D[9990]
    print('walk   : %r' % W['walk'])
    print('key    : %s' % key.hex())
    print('ct(9990): %s' % data.hex())

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(CODE_BASE, 0x10000)
    mu.mem_map(STACK_BASE, 0x10000)
    mu.mem_map(0x300000, 0x4000)
    mu.mem_map(SENTINEL, 0x1000)
    mu.mem_write(CODE_BASE, bytes(D[4485]))
    mu.mem_write(KEY_BASE, bytes(key))
    mu.mem_write(IN_BASE, bytes(data).ljust(48, b'\x00'))
    mu.mem_write(OUT_BASE, b'\x00' * 48)
    mu.mem_write(SENTINEL, b'\xc3')
    rsp = STACK_BASE + 0x10000 - 0x400
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.mem_write(rsp, SENTINEL.to_bytes(8, 'little'))
    for r in (UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI,
              UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8, UC_X86_REG_R9,
              UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13,
              UC_X86_REG_R14, UC_X86_REG_R15):
        mu.reg_write(r, 0)
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RCX, OUT_BASE)
    mu.reg_write(UC_X86_REG_RDX, IN_BASE)
    mu.reg_write(UC_X86_REG_R8, KEY_BASE)
    mu.emu_start(CODE_BASE, SENTINEL, count=200000)
    eax = mu.reg_read(UC_X86_REG_RAX)
    out = bytes(mu.mem_read(OUT_BASE, 64))
    print('eax (strlen) = %d' % eax)
    print('out          : %r' % out)
    flag = out[:eax] if isinstance(eax, int) and 0 < eax <= 64 else out
    print()
    print('FLAG: %r' % flag.decode('ascii', 'replace'))
    pickle.dump({'flag': flag}, open('/tmp/opencode/flag_ch7.pkl', 'wb'))


if __name__ == '__main__':
    main()
