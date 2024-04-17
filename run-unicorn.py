#!/usr/bin/env python

from unicorn.riscv_const import (
    UC_RISCV_REG_A0,
    UC_RISCV_REG_T0,
    UC_RISCV_REG_A1,
    UC_RISCV_REG_A2,
    UC_RISCV_REG_A5,
    UC_RISCV_REG_A7,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_PC,
    UC_RISCV_REG_X10,
    UC_RISCV_REG_X11,
    UC_RISCV_REG_X5,
    # UC_RISCV_REG_UEPCk,
)
from unicorn import (
    Uc,
    UcError,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_INSN,
    UC_HOOK_INTR,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_ARCH_RISCV,
    UC_MODE_RISCV64,
    UC_MODE_RISCV32,
    UC_MEM_WRITE,
)

from elftools.elf.elffile import ELFFile
from pathlib import Path
import struct
import os
from rangetree import RangeTree
from capstone import (
    Cs,
    CS_ARCH_RISCV,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_LITTLE_ENDIAN,
)

# md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)

"""
$ cstool riscv64 1305100093850502
 0  13 05 10 00  addi	a0, zero, 1
 4  93 85 05 02  addi	a1, a1, 0x20
"""
RISCV_CODE = b"\x13\x05\x10\x00\x93\x85\x05\x02"

# memory address where emulation starts
ADDRESS = 0x10000


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    # print(">>> User data: ", user_data)
    print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    # print(">>> User data: ", user_data)
    # print(
    #     ">>> 1 Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size)
    # )
    try:
        data = uc.mem_read(address, size)
        # print(
        #     ">>> 2 Tracing instruction at 0x%x, len(data) %x instruction size = 0x%x"
        #     % (address, len(data), size)
        # )
        # for dd in md.disasm(data, address):
        if len(data) == 0:
            return
        for dd in md.disasm(data, address):
            sp = uc.reg_read(UC_RISCV_REG_SP)
            print(
                f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}: sp_val: 0x{sp:x}"
                # f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}"
            )
    except Exception as e:
        print(f"[TRACING] Error: {e}")
        pass


# callback for tracing memory access (READ or WRITE)
def hook_mem_access(uc, access, address, size, value, user_data):
    if access == UC_MEM_WRITE:
        print(
            ">>> Memory is being WRITE at 0x%x, data size = %u, data value = 0x%x"
            % (address, size, value)
        )
    else:  # READ
        print(">>> Memory is being READ at 0x%x, data size = %u" % (address, size))


# MAX_PROG_SIZE = 0x80000000
# STACK_ADDR = 0x90000000
MAX_PROG_SIZE = 0x00200000
# STACK_ADDR = 0x00200400
# STACK_ADDR = 0x00200400
# static STACK_TOP: u32 = 0x0020_0400;


def init_mem(elf_path: Path, uc: Uc):
    global STACK_ADDR
    elffile = ELFFile(elf_path.open("rb"))
    print("Opening elf file")
    end_addr = 0
    for seg in elffile.iter_segments():
        end_addr = max(end_addr, seg.header.p_vaddr + seg.header.p_memsz)

    # program memory (16 MB)
    prog_size = (end_addr + 0xFFF) & ~0xFFF
    prog_dat = bytearray(prog_size)
    print("malloced 0x%x for program" % prog_size)

    entry = 0x0
    for seg in elffile.iter_segments():
        print(seg.header, hex(seg.header.p_vaddr))
        if seg.header.p_type == "PT_PHDR":
            # print(seg.header.e_entry)
            print("loop entrypoint: ", seg.data())
            # entry = seg.header.p_vaddr
            print("loading segment")
        prog_dat[seg.header.p_vaddr : seg.header.p_vaddr + len(seg.data())] = seg.data()
    #
    entry = elffile.header.e_entry
    # entry = elffile.ehdr.e_entry
    print("entrypoint: 0x%x" % entry)

    # uc.mem_map(0, len(bytes(prog_dat)))
    print("max > len: ", MAX_PROG_SIZE > len(prog_dat))
    print("prog size: ", MAX_PROG_SIZE)
    print("LEN DATA: ", len(prog_dat))
    uc.mem_map(0, MAX_PROG_SIZE)
    # STACK_ADDR = len(bytes(prog_dat)) + 0x100000
    uc.mem_write(0, bytes(prog_dat))
    print("LEN DATA: ", len(prog_dat))
    # for seg in elffile.iter_segments():
    #     print(f"seg: ", seg.header)
    #
    #     data = seg.data()
    #     if seg.header.p_type == "PT_LOAD":
    #         # for dd in md.disasm(data, seg.header.p_vaddr):
    #
    #         page_size = seg.header.p_align
    #         mapsz = page_size * int((len(data) + page_size) / page_size)
    #         expected_mapsz = seg.header.p_memsz
    #         addr = seg.header.p_vaddr - (seg.header.p_vaddr % page_size)
    #         uc.mem_map(addr, mapsz)
    #         print(
    #             f"[INFO] page_size {page_size} - mapsz: {mapsz} - len(data): {len(data)} - addr: {addr}"
    #         )
    #         print("expected_mapsz: ", expected_mapsz)
    #
    #         # print(f"[DEBUG] Mapping addr 0x{hex(addr)} - size: {hex(mapsz)}")
    #         uc.mem_write(addr, data)
    #         # print("[DEBUG] Mapping done!")

    print("mem has been init")
    return entry, end_addr


def init_stack(uc: Uc):
    global STACK_ADDR
    # stack_addr = STACK_ADDR
    stack_addr = MAX_PROG_SIZE
    stack_pointer = stack_addr + 0x400
    stack_size = 0x2000000
    # STACK_TOP = 0x00200400
    print(f"Mapping stack addr 0x{hex(stack_addr)} - size: {hex(stack_size)}")
    uc.mem_map(stack_addr, stack_size)
    print("[DEBUG] Mapping done!")
    # uc.reg_write(UC_RISCV_REG_SP, stack_pointer)
    # uc.reg_write(UC_RISCV_REG_SP, STACK_TOP)
    print("Stack has been init")


# def init_regs(uc: Uc):
#     pass


def hook_intr(uc, intno, user_data):
    # only handle Linux syscall
    t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
    print("[instr] got syscall 0x%x ???" % t0)
    print("[instr] user data", user_data)
    try:
        # a0 = uc.reg_read(UC_RISCV_REG_A0)
        # a2 = uc.reg_read(UC_RISCV_REG_A2)
        # a7 = uc.reg_read(UC_RISCV_REG_A7)
        t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
        a0 = uc.reg_read(UC_RISCV_REG_A0)  # fd
        a1 = uc.reg_read(UC_RISCV_REG_A1)  # addr
        a2 = uc.reg_read(UC_RISCV_REG_A2)  # size
        if t0 == 0x2:
            data = uc.mem_read(a1, a2)
            print(
                "[SYSCALL] got syscall `%s` - `write`???" % data.decode("utf-8").strip()
            )
        if t0 == 0x0:
            # data = uc.mem_read(a1, a2)
            print("[SYSCALL] got syscall - `HALT!`")
            uc.emu_stop()
        # return
        # x11 = uc.reg_read(UC_RISCV_REG_X11)
        # name = md.insn_name(intno)
        # print("[SYSCALL] got syscall 0x%x - `%s`???" % (intno, name))
        # print("[SYSCALL] t0: 0x%x" % t0)
        # print("[SYSCALL] a0: 0x%x" % a0)
        # print("[SYSCALL] a1: 0x%x" % a1)
        # print("[SYSCALL] a2: 0x%x" % a2)
        # print("[SYSCALL] a0: 0x%x" % a0)
        # print("[SYSCALL] a2: 0x%x" % a2)
        # print("[SYSCALL] a7: 0x%x" % a7)
    except Exception as e:
        print("[instr] failed to get instr name for got syscall 0x%x ???" % intno)
        print("[instr] Error: ", e)

    # if intno != 0x80:
    # print("[instr] got interrupt 0x%x ???" % intno)
    # uc.emu_stop()
    # return


def hook_syscall(uc, user_data):
    # only handle Linux syscall
    try:
        x5 = uc.reg_read(UC_RISCV_REG_X5)
        t0 = uc.reg_read(UC_RISCV_REG_T0)
        x10 = uc.reg_read(UC_RISCV_REG_X10)
        x11 = uc.reg_read(UC_RISCV_REG_X11)
        # name = md.insn_name(intno)
        # print("[SYSCALL] got syscall 0x%x - `%s`???" % (intno, name))
        print("[SYSCALL] x5: 0x%x" % x5)
        print("[SYSCALL] t0: 0x%x" % t0)
        print("[SYSCALL] x10: 0x%x" % x10)
        print("[SYSCALL] x11: 0x%x" % x11)
    except Exception as e:
        print("[SYSCALL] failed to get instr name for got syscall 0x%x ???" % intno)
        print("[SYSCALL] Error: ", e)

    # if intno != 0x80:
    #     print("[SYSCALL] got interrupt 0x%x ???" % intno)
    #     uc.emu_stop()
    #     return


def run(uc: Uc, entry: int = 0x0, end_addr: int = 0x0):
    start_addr = 0
    # start_addr = 0x10278
    # end_addr = 0x101F0
    # end_addr = 0x102CC
    # tracing all basic blocks with customized callback
    # elf_path = Path("riscv")
    # elf_path = Path(
    #     "../rust-cross/target/riscv32im-succinct-zkvm-elf/release/rust-cross"
    # )
    # elffile = ELFFile(elf_path.open("rb"))
    # entry = elffile.header.e_entry
    # print("entrypoint: 0x%x" % entry)
    # end_addr = 0
    # for seg in elffile.iter_segments():
    #     end_addr = max(end_addr, seg.header.p_vaddr + seg.header.p_memsz)
    uc.hook_add(UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_intr)
    # uc.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_RISCV_REG_A7)
    # uc.hook_add(UC_HOOK_INSN, hook_syscall)
    # uc.hook_add(UC_HOOK_CODE, hook_code)
    # uc.hook_add(UC_HOOK_INSN, hook_in)
    # uc.hook_add(UC_HOOK_INSN, hook_out, None, 1, 0, UC_X86_INS_OUT)

    # emulate machine code in infinite time
    # uc.emu_start(start_addr, end_addr)
    print("entry: 0x%x" % entry)
    print("end_addr: ", end_addr)
    # uc.emu_start(entry, end_addr)
    uc.emu_start(entry, 0x159ED, count=0x3000)
    # uc.emu_start(entry, 0x13A6C, count=0x1000)


# Test RISCV
def test_riscv():
    print("Emulate RISCV code")
    try:
        # Initialize emulator in RISCV64 mode
        # mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)

        # elf_path = Path("riscv")
        elf_path = Path(
            # "riscv"
            # "../rust-cross/target/riscv32im-succinct-zkvm-elf/release/rust-cross"
            # "/home/semar/Work/rust-riscv/target/riscv32im-risc0-zkvm-elf/release/rust-riscv"
            "/home/semar/Work/rust-riscv/target/riscv32im-succinct-zkvm-elf/release/rust-riscv"
            # "../rust-cross/target/riscv64gc-unknown-none-elf/release/rust-cross"
            # "../rust-cross/target/riscv64gc-unknown-linux-gnu/release/rust-cross"
            # "../rust-cross/target/riscv64gc-unknown-linux-musl/release/rust-cross"
        )
        # elf_path = Path(
        #     "../rust-cross/target/riscv64gc-unknown-linux-musl/release/rust-cross"
        # )
        entry, end_addr = init_mem(elf_path, mu)
        init_stack(mu)
        # now print out some registers
        run(mu, entry, end_addr)
        print(">>> Emulation done. Below is the CPU context")

        a0 = mu.reg_read(UC_RISCV_REG_A0)
        a1 = mu.reg_read(UC_RISCV_REG_A1)
        a5 = mu.reg_read(UC_RISCV_REG_A5)
        print(">>> A0 = 0x%x" % a0)
        print(">>> A1 = 0x%x" % a1)
        print(">>> A5 = 0x%x" % a5)

    except UcError as e:
        print("UC ERROR ERROR: %s" % e)


def test_riscv_original():
    print("Emulate RISCV code")
    try:
        # Initialize emulator in RISCV64 mode
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, RISCV_CODE)

        # initialize machine registers
        mu.reg_write(UC_RISCV_REG_A0, 0x1234)
        # mu.reg_write(UC_RISCV_REG_A1, 0x7890)
        mu.reg_write(UC_RISCV_REG_A1, 0x0020)

        # tracing all basic blocks with customized callback
        mu.hook_add(UC_HOOK_BLOCK, hook_block)

        # tracing all instructions with customized callback
        mu.hook_add(UC_HOOK_CODE, hook_code)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(RISCV_CODE))

        # now print out some registers
        print(">>> Emulation done. Below is the CPU context")

        a0 = mu.reg_read(UC_RISCV_REG_A0)
        a1 = mu.reg_read(UC_RISCV_REG_A1)
        print(">>> A0 = 0x%x" % a0)
        print(">>> A1 = 0x%x" % a1)

    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == "__main__":
    test_riscv()
