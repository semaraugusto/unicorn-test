#!/usr/bin/env python

import struct
import numpy as np
from unicorn.riscv_const import (
    UC_RISCV_REG_A0,
    UC_RISCV_REG_T0,
    UC_RISCV_REG_T3,
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
    UC_MEM_WRITE,
    UC_MEM_READ,
    UC_MEM_FETCH,
    UC_MEM_READ_UNMAPPED,
    UC_MEM_WRITE_UNMAPPED,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_WRITE_PROT,
    UC_MEM_FETCH_PROT,
    UC_MEM_READ_AFTER,
    UC_HOOK_MEM_INVALID,
)

from safetensors import safe_open
from datasets import load_dataset
from syscall_constants import RiscvSyscalls, ZKVMSyscalls
from elftools.elf.elffile import ELFFile
from pathlib import Path
from capstone import (
    Cs,
    CS_ARCH_RISCV,
    CS_MODE_RISCV32,
    CS_MODE_RISCV64,
    CS_MODE_LITTLE_ENDIAN,
)

md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
# md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)


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
        for dd in md.disasm(data, address):
            sp = uc.reg_read(UC_RISCV_REG_SP)
            if dd.mnemonic == "ecall":
                print(
                    f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}: sp_val: 0x{sp:x}"
                    # f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}"
                )
    #         print(
    #             f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}: sp_val: 0x{sp:x}"
    #             # f"[TRACING] 0x{dd.address:x}:\t{dd.mnemonic}\t{dd.op_str}"
    #         )
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
MODEL_START = TOKENIZER_END
MODEL_MAX_SIZE = 0x2000_0000
MODEL_END = MODEL_START + MODEL_MAX_SIZE
STACK_START = MODEL_END


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
    print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    packed_bytes = struct.pack(f"<{len(tokenizer_bytes)}s", bytearray(tokenizer_bytes))
    print("[HERE] bytes[0:12]: ", list(map(int, packed_bytes[:12])))
    uc.mem_write(TOKENIZER_START, struct.pack("<I", 0x67676D6C))
    uc.mem_write(TOKENIZER_START + 4, struct.pack("<I", len(tokenizer_bytes)))
    uc.mem_write(TOKENIZER_START + 8, packed_bytes)
    print("done loading tokenizer")

def load_model(model_path: Path, uc: Uc):
    global MODEL_START, MODEL_MAX_SIZE
    print("loading tokenizer")
    # tokenizer_bytes = tokenizer_path.open("rb").read()
    addr = MODEL_START
    uc.mem_map(MODEL_START, MODEL_MAX_SIZE)
    with safe_open(model_path, framework="pt", device="cpu") as f:
        num_tensors = len(f.keys())
        print(f"num_tensors: {num_tensors}")
        uc.mem_write(addr, struct.pack("<I", 0x67676D6C))
        addr += 4
        uc.mem_write(addr, struct.pack("<I", num_tensors))
        print("num_tensors packed: ", struct.pack("<I", num_tensors))
        addr += 4
        for key in f.keys():
            tensor = f.get_tensor(key)
            print(f"key: {key}, tensor: {tensor}")
            name_bytes = struct.pack(f"<{len(key)}s", key.encode("utf-8"))
            name_len = len(name_bytes)
            uc.mem_write(addr, struct.pack("<I", name_len))
            addr += 4
            uc.mem_write(addr, name_bytes)
            addr += name_len
            print(f"name_len: {name_len}, name_bytes: {name_bytes}")
            uc.mem_write(addr, struct.pack("<I", tensor.dim()))
            addr += 4
            print(f"tensor_dim: {tensor.dim()}")
            for dim in range(tensor.dim()):
                uc.mem_write(addr, struct.pack("<I", tensor.shape[dim]))
                addr += 4
                print(f"tensor.shape[dim]: {tensor.shape[dim]}")

            tensor_bytes = tensor.numpy().astype(np.float32).tobytes()
            tensor_packed = struct.pack(f"<{len(tensor_bytes)}s", tensor_bytes)
            uc.mem_write(addr, tensor_packed)
            addr += len(tensor_packed)


    # assert len(tokenizer_bytes) + 4 <= TOKENIZER_MAX_SIZE, "INCONSISTENT TOKENIZER SIZE"
    # print(
    #     f"Mapping tokenizer addr 0x{hex(TOKENIZER_START)} - size: {hex(len(tokenizer_bytes))}"
    # )
    # uc.mem_map(TOKENIZER_START, TOKENIZER_MAX_SIZE)
    # print("done mapping tokenizer")
    # print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # packed_bytes = struct.pack(f"<{len(tokenizer_bytes)}s", bytearray(tokenizer_bytes))
    # print("[HERE] bytes[0:12]: ", list(map(int, packed_bytes[:12])))
    uc.mem_write(MODEL_START, struct.pack("<I", 0x67676D6C))
    # uc.mem_write(MODEL_START + 4, struct.pack("<I", len(tokenizer_bytes)))
    # uc.mem_write(MODEL_START + 8, packed_bytes)
    print("done loading tokenizer")

def load_input(uc: Uc):
    global TOKENIZER_START, TOKENIZER_MAX_SIZE
    print("loading tokenizer")
    # tokenizer_bytes = tokenizer_path.open("rb").read()
    addr = TOKENIZER_START
    uc.mem_map(TOKENIZER_START, TOKENIZER_MAX_SIZE)
    dataset = load_dataset("mnist")
    # print(f"dataset {dataset}")
    test_image = np.array(dataset["test"][0]['image'])
    print(f"test_image {test_image}")
    # print(f"test_image {test_image.dtype}")
    # print(f"test_image {test_image.shape}")
    uc.mem_write(addr, struct.pack("<I", test_image.shape[0]))
    addr += 4
    uc.mem_write(addr, struct.pack("<I", test_image.shape[1]))
    addr += 4
    num_elements = test_image.shape[0] * test_image.shape[1]
    packed_image = struct.pack(f"<{num_elements}s", bytearray(test_image.tobytes()))
    uc.mem_write(addr, packed_image)
    addr += len(packed_image)
    # num_tensors = len(f.keys())
    # print(f"num_tensors: {num_tensors}")
    # uc.mem_write(addr, struct.pack("<I", 0x67676D6C))
    # addr += 4
    # uc.mem_write(addr, struct.pack("<I", num_tensors))
    # addr += 4
    # for key in f.keys():
    #     tensor = f.get_tensor(key)
    #     print(f"key: {key}, tensor: {tensor}")
    #     name_bytes = struct.pack(f"<{len(key)}s", key.encode("utf-8"))
    #     name_len = len(name_bytes)
    #     uc.mem_write(addr, struct.pack("<I", name_len))
    #     addr += 4
    #     uc.mem_write(addr, name_bytes)
    #     addr += name_len
    #     print(f"name_len: {name_len}, name_bytes: {name_bytes}")
    #     uc.mem_write(addr, struct.pack("<I", tensor.dim()))
    #     addr += 4
    #     print(f"tensor_dim: {tensor.dim()}")
    #     for dim in range(tensor.dim()):
    #         uc.mem_write(addr, struct.pack("<I", tensor.shape[dim]))
    #         addr += 4
    #         print(f"tensor.shape[dim]: {tensor.shape[dim]}")
    #
    #     tensor_bytes = tensor.numpy().astype(np.float32).tobytes()
    #     tensor_packed = struct.pack(f"<{len(tensor_bytes)}s", tensor_bytes)
    #     uc.mem_write(addr, tensor_packed)
    #     addr += len(tensor_packed)


    # assert len(tokenizer_bytes) + 4 <= TOKENIZER_MAX_SIZE, "INCONSISTENT TOKENIZER SIZE"
    # print(
    #     f"Mapping tokenizer addr 0x{hex(TOKENIZER_START)} - size: {hex(len(tokenizer_bytes))}"
    # )
    # uc.mem_map(TOKENIZER_START, TOKENIZER_MAX_SIZE)
    # print("done mapping tokenizer")
    # print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # print(f"writing len {len(tokenizer_bytes)=} of tokenizer to 0x%x" % TOKENIZER_START)
    # packed_bytes = struct.pack(f"<{len(tokenizer_bytes)}s", bytearray(tokenizer_bytes))
    # print("[HERE] bytes[0:12]: ", list(map(int, packed_bytes[:12])))
    uc.mem_write(MODEL_START, struct.pack("<I", 0x67676D6C))
    # uc.mem_write(MODEL_START + 4, struct.pack("<I", len(tokenizer_bytes)))
    # uc.mem_write(MODEL_START + 8, packed_bytes)
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
    stack_addr = MODEL_END + 0x1000
    stack_size = 0x20000000
    stack_pointer = stack_addr + (stack_size//2)
    print(f"Mapping stack addr 0x{hex(stack_addr)} - size: {hex(stack_size)}")
    uc.reg_write(UC_RISCV_REG_SP, stack_pointer)
    uc.mem_map(stack_addr, stack_size)
    print("Stack has been init")


def hook_intr(uc, intno, user_data):
    t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
    try:
        t0 = uc.reg_read(UC_RISCV_REG_T0)  # syscall number
        a0 = uc.reg_read(UC_RISCV_REG_A0)  # fd
        a1 = uc.reg_read(UC_RISCV_REG_A1)  # addr
        a2 = uc.reg_read(UC_RISCV_REG_A2)  # size
        a7 = uc.reg_read(UC_RISCV_REG_A7)  # fd
        # print("[SYSCALL] t0: 0x%x a7: 0x%x a7: %d:" % (t0, a7, a7))
        print("[SYSCALL] t0: 0x%x a7: 0x%x a7: %d: args(%d %d %d)" % (t0, a7, a7, a0, a1, a2))
        match t0:
        # match a7:
            # case RiscvSyscalls.SYS_getuid.value:
            #     print("[SYSCALL] `SYS_getuid!` IGNORING!")
            # case RiscvSyscalls.SYS_geteuid.value:
            #     print("[SYSCALL] `SYS_geteuid!` IGNORING!")
            # case RiscvSyscalls.SYS_geteid.value:
            #     print("[SYSCALL] `SYS_geteid!` IGNORING!")
            # case RiscvSyscalls.SYS_getegid.value:
            #     print("[SYSCALL] `SYS_getegid!` IGNORING!")
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
                # raise Exception(f"[SYSCALL] [UNKNOWN] 0x{intno:x} - `0x{t0:x}`???")
        # match t0:
        #     # case 0x2:
        #     case ZKVMSyscalls.WRITE.value:
        #         # if t0 == 0x2:
        #         data = uc.mem_read(a1, a2)
        #         print("[SYSCALL] [WRITE] `%s`" % data.decode("utf-8").strip())
        #     # case 0x0:
        #     case ZKVMSyscalls.HALT.value:
        #         # data = uc.mem_read(a1, a2)
        #         print("[SYSCALL] [HALT!]")
        #         uc.emu_stop()
        #     case ZKVMSyscalls.SHA_EXTEND.value:
        #         # This seems to happen right after program exits.
        #         # I think we can stop emulation here.
        #         print("[SYSCALL] [SHA_EXTEND!]. EXECUTION IS DONE. HALTING!")
        #         uc.emu_stop()
        #     case ZKVMSyscalls.SHA_COMPRESS.value:
        #         print("[SYSCALL] [SHA_COMPRESS!] - `SHA_COMPRESS!` IGNORING!")
        #     case ZKVMSyscalls.COMMIT.value:
        #         print("[SYSCALL] [COMMIT!] - `COMMIT!` IGNORING!")
        #     case _:
        #         print("[SYSCALL] [UNKNOWN] 0x%x - `0x%x`???" % (intno, t0))
        #         # raise Exception(f"[SYSCALL] [UNKNOWN] 0x{intno:x} - `0x{t0:x}`???")
    except Exception as e:
        print("[instr] failed to get instr name for got intno 0x%x ???" % intno)
        print("[instr] failed to get instr name for got syscall 0x%x ???" % t0)
        print("[instr] Error: ", e)


def hook_mem_invalid(uc, access, address, size, value, user_data):
    """For Debugging Use Only"""
    eip = uc.reg_read(UC_RISCV_REG_PC)
    t3 = uc.reg_read(UC_RISCV_REG_T3)
    print("T3: 0x%x" % t3)
    if access == UC_MEM_WRITE:
        print("invalid WRITE of 0x%x at 0x%X, data size = %u, data value = 0x%x" % (address, eip, size, value))
    if access == UC_MEM_READ:
        print("invalid READ of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH:
        print("UC_MEM_FETCH of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_READ_UNMAPPED:
        print("UC_MEM_READ_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_WRITE_UNMAPPED:
        print("UC_MEM_WRITE_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH_UNMAPPED:
        print("UC_MEM_FETCH_UNMAPPED of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_WRITE_PROT:
        print("UC_MEM_WRITE_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_FETCH_PROT:
        print("UC_MEM_FETCH_PROT of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    if access == UC_MEM_READ_AFTER:
        print("UC_MEM_READ_AFTER of 0x%x at 0x%X, data size = %u" % (address, eip, size))
    return False

def run(uc: Uc, entry: int = 0x0, end_addr: int = 0x0):
    uc.hook_add(UC_HOOK_BLOCK, hook_block)

    # tracing all instructions with customized callback
    uc.hook_add(UC_HOOK_CODE, hook_code)
    uc.hook_add(UC_HOOK_INTR, hook_intr)
    uc.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

    print("entry: 0x%x" % entry)
    print("end_addr: ", end_addr)
    # uc.emu_start(entry, end_addr)
    SECOND = 1_000_000  # (unicorn uses microseconds apparently)
    MINUTE = 60 * SECOND
    try:
        # uc.reg_write(UC_RISCV_REG_PC, entry)
        # entry = 0x000ce002a
        # uc.reg_write(UC_RISCV_REG_PC, entry)
        # uc.emu_start(entry, end_addr, timeout=1 * MINUTE, count=0x200)
        uc.emu_start(entry, end_addr, timeout=30 * SECOND)
        # uc.emu_start(entry, end_addr, timeout=1 * MINUTE)
    except KeyboardInterrupt as e:
        print("KeyboardInterrupt: %s" % e)
        uc.emu_stop()


# Test RISCV
def test_riscv():
    print("Emulate RISCV code")
    # uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV32 + CS_MODE_LITTLE_ENDIAN)
    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
    try:
        # Initialize emulator in RISCV64 mode
        # mu = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 + CS_MODE_LITTLE_ENDIAN)
        model_path = Path(
            "./linear.safetensors"
        )

        elf_path = Path(
            # "../rust-cross/target/riscv32im-succinct-zkvm-elf/release/rust-cross"
            "../rust-cross/target/riscv64im-unicorn-zkvm-elf/release/rust-cross"
            # "../rust-cross/target/riscv64gc-unknown-none-elf/release/rust-cross"
            # "../rust-riscv/target/riscv64gc-unknown-linux-gnu/release/rust-riscv"
            # "../rust-riscv/target/riscv64gc-unknown-linux-musl/release/rust-riscv"
        )
        tokenizer_path = Path(
            "/home/semar/.cache/huggingface/hub/models--stabilityai--stablelm-3b-4e1t/snapshots/fa4a6a92fca83c3b4223a3c9bf792887090ebfba/tokenizer.json"
        )
        entry, end_addr = init_mem(elf_path, uc)
        load_model(model_path, uc)
        load_input(uc)
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
