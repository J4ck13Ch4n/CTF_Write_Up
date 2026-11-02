#!/usr/bin/env python3
"""FlareCalc - fast emulator for one DFA node stub.

The node stub (a small x86-64 function) is called with
    cl  = candidate input character
    rdx = pointer to the shared 32-byte state buffer
and it also uses r8/r9 freely.  It mixes the character into three bytes of
the state buffer and returns in eax the id of the next node.

The stub contains a deliberate anti-analysis delay loop:

    mov  dword ptr [rsp+0x10], 0
    mov  dword ptr [rsp+8], 0
loop:
    mov  eax, [rsp+8]
    inc  eax
    mov  [rsp+8], eax
    cmp  eax, r9d          ; r9d == 0xF4240
    jb   loop
    ...                    ; several more instructions
    sub  eax, 0x6A4AE6E0

The loop accumulates 1+2+...+999999 = 499999500000 = 0x6A4AE6E0 (mod 2**32)
into [rsp+0x10] and the code after it subtracts that constant again, so the
loop is arithmetically a no-op.  To run the stub in microseconds we patch

    mov r9d, 0xF4240        ->  mov r9d, 0         (loop runs 0 times)
    mov dword [rsp+0x10],0  ->  mov dword [rsp+0x10], 0x6A4AE6E0

which keeps the arithmetic identical while removing the million iterations.
"""
import os
import sys

import capstone
from unicorn import UC_ARCH_X86, UC_MODE_64, Uc, UcError
from unicorn.x86_const import (UC_X86_REG_CL, UC_X86_REG_R8,
                               UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RSP,
                               UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RSI,
                               UC_X86_REG_RDI, UC_X86_REG_RBP,
                               UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
                               UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
                               UC_X86_REG_R15, UC_X86_REG_EFLAGS)

ZERO_REGS = (UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
             UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
             UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
             UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15)

CODE_BASE = 0x100000
STACK_BASE = 0x200000
STATE_BASE = 0x300000
SENTINEL = 0x400000
CODE_SIZE = 0x10000
STACK_SIZE = 0x10000
STATE_SIZE = 0x1000

PATCH_LOOP_BOUND = b'\x41\xb9\x40\x42\x0f\x00'      # mov r9d, 0xF4240
PATCH_LOOP_BOUND_NEW = b'\x41\xb9\x00\x00\x00\x00'  # mov r9d, 0
PATCH_ACC_INIT = b'\xc7\x44\x24\x10\x00\x00\x00\x00'      # mov dword [rsp+0x10], 0
PATCH_ACC_INIT_NEW = b'\xc7\x44\x24\x10\xe0\xe6\x4a\x6a'  # ... = 0x6A4AE6E0
STALL_SUM = 0x6A4AE6E0
STALL_BOUND = 0xF4240

_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_MD.detail = True
import capstone.x86 as _x86


def patch_code(code):
    """Neutralise a stub's anti-analysis delay loop, generically.

    The stub contains a delay loop accumulating sum(1..999999) = 0x6A4AE6E0
    into a stack dword, bounded by ``mov reg32, 0xF4240``:

        mov  dword [rsp+dacc], 0      ; accumulator init
        mov  dword [rsp+dcnt], 0      ; counter init
    body:                                ; do-while (style: test at the end)
        add  ecx, eax ; mov [rsp+dacc], ecx     (acc += counter)
        inc  eax      ; mov [rsp+dcnt], eax     (counter += 1)
        cmp  eax, reg32 / jb body

    The registers and stack displacements vary from node to node, so:
      * find ``mov reg32, 0xF4240`` and set the immediate to 0;
      * find the counter slot as the stack store whose previous instruction
        is ``inc`` on the same register, and the accumulator slot as the
        ``mov dword [rsp+d], 0`` init whose displacement differs from it;
      * rewrite the accumulator init's immediate to 0x6A4AE6E0.

    With the bound at 0, the loop executes exactly one harmless iteration
    (acc += 0) and the accumulator keeps the value the real million-iteration
    loop would produce, so the arithmetic is identical.
    """
    b = bytearray(code)
    insns = list(_MD.disasm(bytes(b), 0))
    insns = [i for i in insns if i.address + i.size <= len(b)]

    bound_hits = []
    for insn in insns:
        if insn.mnemonic not in ('mov', 'movabs'):
            continue
        imm_ops = [o for o in insn.operands if o.type == _x86.X86_OP_IMM
                   and o.imm == STALL_BOUND]
        if imm_ops and 'dword ptr' not in insn.op_str:
            bound_hits.append(insn)
    if not bound_hits:
        raise ValueError('delay-loop bound (mov reg32, 0xF4240) not found')

    # counter slot: ``mov [rsp+d], reg`` right after ``inc reg``
    counter_disp = None
    for idx, insn in enumerate(insns):
        if idx == 0 or insn.mnemonic != 'mov' or insn.bytes[0] != 0x89:
            continue
        prev = insns[idx - 1]
        if prev.mnemonic == 'inc' and prev.op_str:
            sreg = insn.op_str.split(',', 1)[1].strip()
            if sreg == prev.op_str.strip() and '[rsp' in insn.op_str:
                counter_disp = insn.op_str
                break
    # zero-init stack dwords (opcode 0xc7)
    zero_inits = [i for i in insns if i.mnemonic == 'mov' and i.bytes[0] == 0xc7
                  and 'dword ptr [rsp' in i.op_str
                  and (not counter_disp or counter_disp not in i.op_str)
                  and any(o.type == _x86.X86_OP_IMM and o.imm == 0
                          for o in i.operands)]
    if not zero_inits:
        raise ValueError('accumulator init (mov dword [rsp+..], 0) not found')
    # patch its trailing imm32
    insn = zero_inits[0]
    b[insn.address + insn.size - 4:insn.address + insn.size] = \
        STALL_SUM.to_bytes(4, 'little')
    # set every bound immediate to 0
    for insn in bound_hits:
        b[insn.address + insn.size - 4:insn.address + insn.size] = \
            (0).to_bytes(4, 'little')
    return bytes(b), True


class Emulator:
    """One persistent unicorn instance; run() is re-entrant and cheap."""

    def __init__(self):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu = self.mu
        mu.mem_map(CODE_BASE, CODE_SIZE)
        mu.mem_map(STACK_BASE, STACK_SIZE)
        mu.mem_map(STATE_BASE, STATE_SIZE)
        mu.mem_map(SENTINEL, 0x1000)
        mu.mem_write(SENTINEL, b'\xcc' * 0x1000)
        self.rsp = STACK_BASE + STACK_SIZE - 0x200
        mu.reg_write(UC_X86_REG_RSP, self.rsp)

    def run(self, code, char, state, count=500000):
        """'' -> (eax, new_state).  Raises UcError on a broken stub."""
        mu = self.mu
        patched, _ = patch_code(code)
        mu.mem_write(CODE_BASE, bytes(patched).ljust(CODE_SIZE, b'\x00')[
            :CODE_SIZE])
        # unicorn keeps translated blocks for old code bytes unless flushed
        mu.ctl_remove_cache(CODE_BASE, CODE_BASE + CODE_SIZE)
        mu.mem_write(STATE_BASE, bytes(state).ljust(STATE_SIZE, b'\x00'))
        # clear the scratch window the stub may read stale values from
        mu.mem_write(self.rsp, b'\x00' * 0x1e0)
        mu.mem_write(self.rsp, SENTINEL.to_bytes(8, 'little'))
        # fresh-register guarantee: nothing from the previous run may leak in
        for r in ZERO_REGS:
            mu.reg_write(r, 0)
        mu.reg_write(UC_X86_REG_EFLAGS, 0)
        mu.reg_write(UC_X86_REG_RSP, self.rsp)
        mu.reg_write(UC_X86_REG_RDX, STATE_BASE)
        mu.reg_write(UC_X86_REG_R8, STATE_BASE)
        mu.reg_write(UC_X86_REG_CL, char & 0xff)
        mu.emu_start(CODE_BASE, SENTINEL, count=count)
        eax = mu.reg_read(UC_X86_REG_RAX)
        new_state = bytes(mu.mem_read(STATE_BASE, 32))
        return eax, new_state


def make_emulator():
    return Emulator()
