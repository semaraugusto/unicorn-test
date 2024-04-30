from enum import Enum


class ZKVMSyscalls(Enum):
    HALT = 0x0
    WRITE = 0x2
    SHA_EXTEND = 0x300105
    SHA_COMPRESS = 0x10106
    COMMIT = 0x10

class RiscvSyscalls(Enum):
    # SYS_geteid = 0xae
    # SYS_geteuid = 0xaf
    SYS_getuid = 174
    SYS_geteid = 175
    SYS_geteuid = 176
    SYS_getegid = 177
    SYS_gettid = 178
    SYS_sysinfo = 179
