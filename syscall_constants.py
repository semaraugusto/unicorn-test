from enum import Enum


class ZKVMSyscalls(Enum):
    HALT = 0x0
    WRITE = 0x2
    SHA_EXTEND = 0x300105
    SHA_COMPRESS = 0x10106
    COMMIT = 0x10
