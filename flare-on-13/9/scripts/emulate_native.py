#!/usr/bin/env python3
"""
NeonOutRun - native part.

The Rust backend replaces three V8 builtins with native FunctionCallbacks:

  * Array.prototype.sort        -> 0x67deb2
  * Math.min                     -> 0x67eb83
  * String.prototype.replaceAll  -> 0x67e81e

The interesting math lives in the Math.min hook: for every finished lap it

  * computes the integer lap time  b = clamp(floor(lap_secs), 0, 255)
  * derives an angle  theta = (pi / M) * (p + s*b)  from a 128 bit PRNG
    that is indexed by the lap counter
  * accumulates  acc2 += v * (N * sin(theta))     (v = |split| * scale)

while the sort hook accumulates  acc1 = sum(|split| * scale).
The game is "won" when |acc1 - acc2| < 1e-6, i.e. when every single lap
contributes exactly its own v.

This module emulates the *real* machine code of the hook with Unicorn so the
PRNG never has to be re-implemented by hand.
"""
import os
import struct
from unicorn import *
from unicorn.x86_const import *

HERE = os.path.dirname(os.path.abspath(__file__))
ELF = os.path.join(os.path.dirname(HERE), 'neon_outrun')

# ---------------------------------------------------------------- ELF loader
class Elf:
    def __init__(self, path):
        self.d = open(path, "rb").read()
        self.segments = []
        phoff = struct.unpack_from("<Q", self.d, 0x20)[0]
        phnum = struct.unpack_from("<H", self.d, 0x38)[0]
        phentsize = struct.unpack_from("<H", self.d, 0x36)[0]
        for i in range(phnum):
            o = phoff + i * phentsize
            t, f, off, va, pa, fsz, msz, al = struct.unpack_from("<IIQQQQQQ", self.d, o)
            if t == 1:
                self.segments.append((va, off, fsz, msz))

    def map_into(self, mu):
        for va, off, fsz, msz in self.segments:
            page = va & ~0xFFF
            end = (va + msz + 0xFFF) & ~0xFFF
            mu.mem_map(page, end - page, UC_PROT_ALL)
            mu.mem_write(va, self.d[off:off + fsz])
        self.apply_relocs(mu)

    def v2o(self, vaddr):
        for va, off, fsz, msz in self.segments:
            if va <= vaddr < va + fsz:
                return off + (vaddr - va)
        raise KeyError(hex(vaddr))

    def apply_relocs(self, mu):
        """Apply R_X86_64_RELATIVE relocations (PIE load base == 0 here).

        The dynamic linker finds them through DT_RELA/DT_RELASZ in .dynamic
        (this binary has no PT_RELA segment for .rela.dyn).
        """
        d = self.d
        dyn_off = self.v2o(0x1422FB0)
        rela = relasz = None
        i = 0
        while True:
            tag, val = struct.unpack_from("<QQ", d, dyn_off + i * 16)
            if tag == 0:
                break
            if tag == 7:
                rela = val
            elif tag == 8:
                relasz = val
            i += 1
        assert rela and relasz, (rela, relasz)
        off = self.v2o(rela)
        n = 0
        for j in range(relasz // 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", d, off + j * 24)
            if (r_info & 0xFFFFFFFF) == 8:      # R_X86_64_RELATIVE
                mu.mem_write(r_off, struct.pack("<Q", r_add & 0xFFFFFFFFFFFFFFFF))
                n += 1
        self.n_relocs = n


def f64(bits):
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


def f64bits(x):
    return struct.unpack("<Q", struct.pack("<d", x))[0]


# ------------------------------------------------------------------ emulator
STACK_BASE = 0x0000_7000_0000_0000
STACK_SIZE = 0x0000_0000_0010_0000
HEAP_BASE = 0x0000_6000_0000_0000
TRAMP_BASE = 0x0000_5000_0000_0000

# --- real code that is emulated ------------------------------------------
A_SCRAMBLE1 = 0x67F9D8      # fn(u8 idx, u8 k) -> u64
A_SCRAMBLE2 = 0x68003E      # fn(u32 k) -> u64
A_FLOOR = 0x13B2930         # f64 floor
A_TRUNC = 0x13B2840         # f64 trunc
A_TAYLOR_SIN = 0x687D80     # sin via Taylor series
A_SIN_SUM = 0x687CFF        # sum of Taylor partial sums

# --- stubbed helpers ------------------------------------------------------
A_ONCE_LOCK = 0x67E633      # OnceLock::get_or_init  (Vec<u8>)
A_VEC_PUSH = 0x687D50       # Vec<u8>::push
A_SET_ACC = 0x5DFF31        # "give me &mut state"
A_GET_ACC = 0x604A82        # "give me &state"
A_DROP = 0x69C4A0           # drop Option
A_RELEASE = 0x68CFCE        # release scope handle

# trampolines (code we write ourselves)
T_POP1 = TRAMP_BASE + 0x00      # pop rbx ; ret
T_POP3 = TRAMP_BASE + 0x10      # add rsp,8 ; pop rbx ; pop r14 ; ret
T_POP4 = TRAMP_BASE + 0x20      # pop rbx ; pop r14 ; pop rbp ; ret
T_RET = TRAMP_BASE + 0x30       # ret


class MinHookEmu:
    """Emulates the pure part of the Math.min hook (0x67eb83)."""

    def __init__(self, elf: Elf):
        self.elf = elf
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        elf.map_into(self.mu)
        self.mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        self.mu.mem_map(HEAP_BASE, 0x10000, UC_PROT_ALL)
        self.mu.mem_map(TRAMP_BASE, 0x1000, UC_PROT_ALL)
        self.mu.mem_write(T_POP1, b"\x5b\xc3")
        self.mu.mem_write(T_POP3, b"\x48\x83\xc4\x08\x5b\x41\x5e\xc3")
        self.mu.mem_write(T_POP4, b"\x5b\x41\x5e\x5d\xc3")
        self.mu.mem_write(T_RET, b"\xc3")
        self.rsp = STACK_BASE + STACK_SIZE - 0x4000
        self.mu.reg_write(UC_X86_REG_RSP, self.rsp)
        # fake state struct: [8] = lap counter
        self.state = HEAP_BASE + 0x100
        self.mu.mem_write(self.state, struct.pack("<QQ", 0, 0))
        # fake Vec<u8> (cap, ptr, len) as used by 0x687d50
        self.vec = HEAP_BASE + 0x200
        self.vecbuf = HEAP_BASE + 0x400
        self.mu.mem_write(self.vec, struct.pack("<QQQ", 64, self.vecbuf, 0))
        # fake accumulator: [8] = acc (f64)
        self.acc = HEAP_BASE + 0x300
        self.mu.mem_write(self.acc, struct.pack("<Qd", 0, 0.0))
        self.pushed = []
        self.stop = None
        self.mu.hook_add(UC_HOOK_CODE, self._code)
        self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                         UC_HOOK_MEM_FETCH_UNMAPPED, self._bad_mem)

    def _bad_mem(self, uc, access, address, size, value, user):
        raise RuntimeError("invalid mem access @ 0x%x (rip=0x%x)" %
                           (address, uc.reg_read(UC_X86_REG_RIP)))

    # ----------------------------------------------------------------- code
    def _code(self, uc, address, size, user):
        if address == self.stop:
            uc.emu_stop()
            return
        if address == A_ONCE_LOCK:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            uc.mem_write(rdi, b"\x00" + b"\x00" * 7 + struct.pack("<Q", self.vec) + b"\x00")
            uc.reg_write(UC_X86_REG_RAX, self.vec)
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return
        if address == A_VEC_PUSH:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            self.pushed.append(rsi & 0xFF)
            ptr = struct.unpack("<Q", uc.mem_read(rdi + 8, 8))[0]
            ln = struct.unpack("<Q", uc.mem_read(rdi + 16, 8))[0]
            uc.mem_write(ptr + ln, bytes([rsi & 0xFF]))
            uc.mem_write(rdi + 16, struct.pack("<Q", ln + 1))
            uc.reg_write(UC_X86_REG_RAX, rsi & 0xFF)
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return
        if address == A_SET_ACC:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            uc.mem_write(rdi, b"\x00" + b"\x00" * 7 + struct.pack("<Q", self.state) + b"\x00")
            uc.reg_write(UC_X86_REG_RAX, self.state)
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return
        if address == A_GET_ACC:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            uc.mem_write(rdi, b"\x00" + b"\x00" * 7 + struct.pack("<Q", self.acc) + b"\x00")
            uc.reg_write(UC_X86_REG_RAX, self.acc)
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return
        if address == A_DROP:
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return
        if address == A_RELEASE:
            uc.reg_write(UC_X86_REG_RIP, T_RET)
            return

    # ------------------------------------------------------------------ run
    def run_lap(self, lap_index, lap_secs, stop=0x67F946):
        mu = self.mu
        mu.mem_write(self.rsp, b"\x00" * 0x200)
        mu.mem_write(self.state + 8, struct.pack("<Q", lap_index))
        mu.mem_write(self.acc, struct.pack("<Qd", 0, 0.0))
        mu.mem_write(self.vec + 16, struct.pack("<Q", 0))
        self.pushed = []
        # 0x8(rsp)  = lap_secs (double)
        # 0x10(rsp) = option flag, 0x18(rsp) = state ptr, 0x20(rsp) = tag
        # 0x30(rsp) = the popped |split|*scale value (irrelevant for the angle)
        mu.mem_write(self.rsp + 0x08, struct.pack("<d", float(lap_secs)))
        mu.mem_write(self.rsp + 0x10, b"\x00" * 24)
        mu.mem_write(self.rsp + 0x18, struct.pack("<Q", self.state))
        mu.mem_write(self.rsp + 0x20, b"\x00")
        mu.mem_write(self.rsp + 0x30, struct.pack("<d", 1.0))
        mu.mem_write(self.rsp + 0x50, struct.pack("<d", float(int(lap_secs))))
        mu.reg_write(UC_X86_REG_R14, lap_index & 0xFFFFFFFF)
        mu.reg_write(UC_X86_REG_RAX, 0)
        self.stop = stop
        try:
            mu.emu_start(0x67ED5B, stop, timeout=60 * 1000 * 1000)
        except UcError as e:
            raise RuntimeError("unicorn error: %s (rip=0x%x)" %
                               (e, mu.reg_read(UC_X86_REG_RIP)))
        p_state_u64 = struct.unpack("<Q", mu.mem_read(self.rsp + 0x28, 8))[0]
        p_byte = mu.mem_read(self.rsp + 0x07, 1)[0]   # sign byte (parity of PRNG out)
        p_M = mu.reg_read(UC_X86_REG_R9)
        p_xmm0 = f64(mu.reg_read(UC_X86_REG_XMM0))
        p_r13 = mu.reg_read(UC_X86_REG_R13)
        acc = struct.unpack("<d", mu.mem_read(self.acc + 8, 8))[0]
        return dict(lap=lap_index, p=p_state_u64, byte=p_byte, M=p_M,
                    xmm0=p_xmm0, r13=p_r13, acc=acc, pushed=list(self.pushed))


def main():
    elf = Elf(ELF)
    emu = MinHookEmu(elf)
    for i in range(6):
        r = emu.run_lap(i, 100.0)
        print("lap %d  p=0x%016x  M=%d  r13=0x%x  byte=%d pushed=%s" %
              (r["lap"], r["p"], r["M"], r["r13"], r["byte"], r["pushed"]))


if __name__ == "__main__":
    main()
