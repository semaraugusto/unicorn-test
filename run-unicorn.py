#!/usr/bin/env python

from unicorn.riscv_const import (
    UC_RISCV_REG_A0,
    UC_RISCV_REG_A1,
    UC_RISCV_REG_A5,
    UC_RISCV_REG_SP,
)
from unicorn import (
    Uc,
    UcError,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_ARCH_RISCV,
    UC_MODE_RISCV64,
    UC_MODE_RISCV32,
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
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
# md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)

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


MAX_PROG_SIZE = 0x80000000
STACK_ADDR = 0x90000000


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
    uc.mem_map(0, MAX_PROG_SIZE)
    # STACK_ADDR = len(bytes(prog_dat)) + 0x100000
    uc.mem_write(0, bytes(prog_dat))
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
    stack_addr = STACK_ADDR
    stack_pointer = stack_addr + 0x100000
    stack_size = 0x20000000
    print(f"Mapping stack addr 0x{hex(stack_addr)} - size: {hex(stack_size)}")
    uc.mem_map(stack_addr, stack_size)
    print("[DEBUG] Mapping done!")
    uc.reg_write(UC_RISCV_REG_SP, stack_pointer)
    print("Stack has been init")


# def init_regs(uc: Uc):
#     pass


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

    # emulate machine code in infinite time
    # uc.emu_start(start_addr, end_addr)
    uc.emu_start(entry, end_addr)


# Test RISCV
def test_riscv():
    print("Emulate RISCV code")
    try:
        # Initialize emulator in RISCV64 mode
        mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
        # mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)

        # elf_path = Path("riscv")
        elf_path = Path(
            # "riscv"
            # "../rust-cross/target/riscv32im-succinct-zkvm-elf/release/rust-cross"
            "../rust-cross/target/riscv64gc-unknown-none-elf/release/rust-cross"
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
