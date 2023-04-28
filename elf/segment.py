'''
Copyright (c) 2023, FlowSwitch <flowswitch@mail.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
	this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
3. The name of the author may not be used to endorse or promote products
   derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
'''

__all__ = ['PT', 'PF', 'ELFSegment', 'ELFSegmentTable']

from struct import calcsize, pack, unpack_from
from enum import IntEnum, IntFlag

from .common import *


class PT(IntEnum):
    NULL = 0
    LOAD = 1
    DYNAMIC = 2
    INTERP = 3
    NOTE = 4
    SHLIB = 5
    PHDR = 6
    TLS = 7
    LOOS = 0x60000000
    HIOS = 0x6FFFFFFF
    LOPROC = 0x70000000
    HIPROC = 0x7fffffff


class PF(IntFlag):
    X = 1   # Execute
    W = 2   # Write
    R = 4   # Read
    MASKPROC = 0xF0000000 # Processor-specific mask


class ELFSegment(ELFItem):
    def __init__(self, bitness=32, data=None):
        super().__init__(bitness)
        self.format = {32: "<8I", 64: "<2I6Q"}[bitness]
        if not data:
            data = b'\0'*calcsize(self.format)
            self.payload = b'' # a placeholder
        self.unpack(data)

    def unpack(self, data):
        self.unpack_from(data)

    def unpack_from(self, data, offset=0):
        if self.bitness==32:
            self.typ, self.offset, self.vaddr, self.paddr, self.filesz, self.memsz, self.flags, self.align = unpack_from(self.format, data, offset)
        elif self.bitness==64:
            self.typ, self.flags, self.offset, self.vaddr, self.paddr, self.filesz, self.memsz, self.align = unpack_from(self.format, data, offset)
        else:
            raise NotImplementedError("Unsupported bitness: "+str(self.bitness))
        if offset: # operating on full ELF
            self.payload = data[self.offset:self.offset+self.filesz]


    def pack(self):
        if self.bitness==32:
            return pack(self.format, self.typ, self.offset, self.vaddr, self.paddr, self.filesz, self.memsz, self.flags, self.align)
        elif self.bitness==64:
            return pack(self.format, self.typ, self.flags, self.offset, self.vaddr, self.paddr, self.filesz, self.memsz, self.align)
        else:
            raise NotImplementedError("Unsupported bitness: "+str(self.bitness))

    def __str__(self):
        if self.bitness==32:
            return "%08X %08X %08X %08X %08X %08X %s %s" % (self.offset, self.vaddr, self.paddr, 
                self.filesz, self.memsz, self.align, str(PT(self.typ)), str(PF(self.flags)))
        elif self.bitness==64:
            return "%016X %016X %016X %016X %016X %016X %s %s" % (self.offset, self.vaddr, self.paddr, 
                self.filesz, self.memsz, self.align, str(PT(self.typ)), str(PF(self.flags)))
        else:
            raise NotImplementedError("Unsupported bitness: "+str(self.bitness))

    def is_unused(self):
        return (self.flags & 0x00E00000)==0x00600000		

    def contains_va(self, va):
        return va>=self.vaddr and va<(self.vaddr+self.memsz)

    def contains_pa(self, pa):
        return pa>=self.paddr and pa<(self.paddr+self.memsz)

    def contains_offset(self, offset):
        return offset>=self.offset and offset<(self.offset+self.filesz)


class ELFSegmentTable(ELFTable):
    def __init__(self, bitness=32):
        super().__init__(ELFSegment, bitness)

    def find_by_va(self, va):
        for sct in self.table:
            if sct.contains_va(va):
                return sct
        return None

    def find_by_pa(self, pa):
        for sct in self.table:
            if sct.contains_pa(pa):
                return sct
        return None

    def find_by_offset(self, offset):
        for sct in self.table:
            if sct.contains_offset(offset):
                return sct
        return None
