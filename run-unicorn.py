#!/usr/bin/env python

import struct
from unicorn.riscv_const import (
    UC_RISCV_REG_A0,
    UC_RISCV_REG_T0,
    UC_RISCV_REG_A1,
    UC_RISCV_REG_A2,
    UC_RISCV_REG_A5,
    UC_RISCV_REG_A7,
    UC_RISCV_REG_SP,
    UC_RISCV_REG_PC,
)
from unicorn import (
    Uc,
    UcError,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_INTR,
    UC_ARCH_RISCV,
    UC_MODE_RISCV64,
    UC_MODE_RISCV32,
    UC_MEM_WRITE,
)

from syscall_constants import ZKVMSyscalls
from elftools.elf.elffile import ELFFile
from pathlib import Path
from capstone import (
    Cs,
    CS_ARCH_RISCV,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_LITTLE_ENDIAN,
)

# md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)


# callback for tracing basic blocks
def hook_block(uc, address, size, user_data):
    # print(">>> User data: ", user_data)
    # print(">>> Tracing basic block at 0x%x, block size = 0x%x" % (address, size))
    pass


# callback for tracing instructions
def hook_code(uc, address, size, user_data):
    try:
        data = uc.mem_read(address, size)
        # print(
        #     ">>> 2 Tracing instruction at 0x%x, len(data) %x instruction size = 0x%x"
        #     % (address, len(data), size)
        # )
        if len(data) == 0:
            return
        # for dd in md.disasm(data, address):
        #     sp = uc.reg_read(UC_RISCV_REG_SP)
        # if dd.mnemonic == "ecall":
        #     print(
        #         f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}: sp_val: 0x{sp:x}"
        #         # f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}"
        #     )
        # print(
        #     f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}: sp_val: 0x{sp:x}"
        #     # f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}"
        # )
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


MAX_PROG_SIZE = 0x10000000
TOKENIZER_START = MAX_PROG_SIZE
TOKENIZER_MAX_SIZE = 0x206000
TOKENIZER_END = TOKENIZER_START + TOKENIZER_MAX_SIZE  # 0x20206000
STACK_START = TOKENIZER_END


def load_tokenizer(tokenizer_path: Path, uc: Uc):
    global TOKENIZER_MAX_SIZE, TOKENIZER_START
    print("loading tokenizer")
    tokenizer_bytes = tokenizer_path.open("rb").read()
    assert len(tokenizer_bytes) + 4 <= TOKENIZER_MAX_SIZE, "INCONSISTENT TOKENIZER SIZE"
    print(
        f"Mapping tokenizer addr 0x{hex(TOKENIZER_START)} - size: {hex(len(tokenizer_bytes))}"
    )
    uc.mem_map(TOKENIZER_START, TOKENIZER_MAX_SIZE)
    print("done mapping tokenizer")
    print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # print(f"writing len {hex(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # print(
    #     f"writing len {bytes(len(tokenizer_bytes))} of tokenizer to 0x%x"
    #     % TOKENIZER_START
    # )
    print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    packed_bytes = struct.pack(f"<{len(tokenizer_bytes)}s", bytearray(tokenizer_bytes))
    # packed_bytes_be = struct.pack(">s", tokenizer_bytes)
    # print("Tokenizer starting bytes[:4]: ", int.from_bytes(packed_bytes_be[:4]))
    # print("Tokenizer starting bytes[4:8]: ", int.from_bytes(packed_bytes_be[4:8]))
    # print("Tokenizer starting bytes[8:12]: ", int.from_bytes(packed_bytes_be[8:12]))
    print("[HERE] bytes[0:12]: ", tokenizer_bytes[:50])
    # print("[HERE] bytes_be[0:12]: ", packed_bytes_be[:12])
    # print("[HERE] bytes_le[0:12]: ", packed_bytes[:12])
    # print("[HERE] bytes_le[0:12]: ", packed_bytes)
    # print("[HERE] bytes[0]: ", int(tokenizer_bytes[0]))
    # print("[HERE] bytes[1]: ", int(tokenizer_bytes[1]))
    # print("[HERE] bytes[2]: ", int(tokenizer_bytes[2]))
    # print("[HERE] bytes[3]: ", int(tokenizer_bytes[3]))
    # print("[HERE] bytes[4]: ", int(tokenizer_bytes[4]))
    # print("[HERE] bytes[5]: ", int(tokenizer_bytes[5]))
    # print("[HERE] bytes[6]: ", int(tokenizer_bytes[6]))
    # print("[HERE] bytes[7]: ", int(tokenizer_bytes[7]))
    # print("[HERE] bytes[8]: ", int(tokenizer_bytes[7]))
    # print("[HERE] bytes[8]: ", int(tokenizer_bytes[7]))
    print("[HERE] bytes[0:12]: ", list(map(int, packed_bytes[:12])))
    uc.mem_write(TOKENIZER_START, struct.pack("<I", 0x67676D6C))
    uc.mem_write(TOKENIZER_START + 4, struct.pack("<I", len(tokenizer_bytes)))
    uc.mem_write(TOKENIZER_START + 8, packed_bytes)
    print("done loading tokenizer")


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
    print("entrypoint: 0x%x" % entry)

    print("max > len: ", MAX_PROG_SIZE > len(prog_dat))
    print("prog size: ", MAX_PROG_SIZE)
    print("LEN DATA: ", len(prog_dat))
    uc.mem_map(0, MAX_PROG_SIZE)
    uc.mem_write(0, bytes(prog_dat))
    print("LEN DATA: ", len(prog_dat))

    print("mem has been init")
    return entry, end_addr


def init_stack(uc: Uc):
    global TOKENIZER_END
    # stack_addr = STACK_ADDR
    stack_addr = TOKENIZER_END
    stack_pointer = stack_addr + 0x400
    stack_size = 0x2000000
    print(f"Mapping stack addr 0x{hex(stack_addr)} - size: {hex(stack_size)}")
    uc.mem_map(stack_addr, stack_size)
    print("Stack has been init")


def hook_intr(uc, intno, user_data):
    t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
    try:
        t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
        a0 = uc.reg_read(UC_RISCV_REG_A0)  # fd
        a1 = uc.reg_read(UC_RISCV_REG_A1)  # addr
        a2 = uc.reg_read(UC_RISCV_REG_A2)  # size
        match t0:
            # case 0x2:
            case ZKVMSyscalls.WRITE.value:
                # if t0 == 0x2:
                data = uc.mem_read(a1, a2)
                print("[SYSCALL] [WRITE] `%s`" % data.decode("utf-8").strip())
            # case 0x0:
            case ZKVMSyscalls.HALT.value:
                # data = uc.mem_read(a1, a2)
                print("[SYSCALL] [HALT!]")
                uc.emu_stop()
            case ZKVMSyscalls.SHA_EXTEND.value:
                # This seems to happen right after program exits.
                # I think we can stop emulation here.
                print("[SYSCALL] [SHA_EXTEND!]. EXECUTION IS DONE. HALTING!")
                uc.emu_stop()
            case ZKVMSyscalls.SHA_COMPRESS.value:
                print("[SYSCALL] [SHA_COMPRESS!] - `SHA_COMPRESS!` IGNORING!")
            case ZKVMSyscalls.COMMIT.value:
                print("[SYSCALL] [COMMIT!] - `COMMIT!` IGNORING!")
            case _:
                print("[SYSCALL] [UNKNOWN] 0x%x - `0x%x`???" % (intno, t0))
                raise Exception(f"[SYSCALL] [UNKNOWN] 0x{intno:x} - `0x{t0:x}`???")
    except Exception as e:
        print("[instr] failed to get instr name for got syscall 0x%x ???" % intno)
        print("[instr] Error: ", e)


def run(uc: Uc, entry: int = 0x0, end_addr: int = 0x0):
    uc.hook_add(UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_intr)

    print("entry: 0x%x" % entry)
    print("end_addr: ", end_addr)
    # uc.emu_start(entry, end_addr)
    SECOND = 1_000_000  # (unicorn uses microseconds apparently)
    try:
        uc.emu_start(entry, end_addr, timeout=5 * SECOND)
    except KeyboardInterrupt as e:
        print("KeyboardInterrupt: %s" % e)
        uc.emu_stop()


# Test RISCV
def test_riscv():
    print("Emulate RISCV code")
    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)
    try:
        # Initialize emulator in RISCV64 mode
        # mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)

        elf_path = Path(
            "../rust-cross/target/riscv32im-succinct-zkvm-elf/release/rust-cross"
            # "../rust-cross/target/riscv64gc-unknown-none-elf/release/rust-cross"
        )
        tokenizer_path = Path(
            "/home/semar/.cache/huggingface/hub/models--stabilityai--stablelm-3b-4e1t/snapshots/fa4a6a92fca83c3b4223a3c9bf792887090ebfba/tokenizer.json"
        )
        entry, end_addr = init_mem(elf_path, uc)
        load_tokenizer(tokenizer_path, uc)
        init_stack(uc)
        # now print out some registers
        run(uc, entry, end_addr)
        print(">>> Emulation done. Below is the CPU context")

        a0 = uc.reg_read(UC_RISCV_REG_A0)
        a1 = uc.reg_read(UC_RISCV_REG_A1)
        a5 = uc.reg_read(UC_RISCV_REG_A5)
        print(">>> A0 = 0x%x" % a0)
        print(">>> A1 = 0x%x" % a1)
        print(">>> A5 = 0x%x" % a5)

    except UcError as e:
        print("UC ERROR ERROR: %s" % e)

    except KeyboardInterrupt as e:
        print("KeyboardInterrupt: %s" % e)
        uc.emu_stop()


if __name__ == "__main__":
    test_riscv()
