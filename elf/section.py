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

__all__ = ['SHT', 'ELFSection', 'ELFSectionTable']

from struct import pack, unpack_from, calcsize
from enum import IntEnum, IntFlag

from .common import *


class SHT(IntEnum):
    NULL = 0
    PROGBITS = 1
    SYMTAB = 2
    STRTAB = 3
    RELA = 4
    HASH = 5
    DYNAMIC = 6
    NOTE = 7
    NOBITS = 8
    REL = 9
    SHLIB = 10
    DYNSYM = 11
    INIT_ARRAY = 14
    FINI_ARRAY = 15
    PREINIT_ARRAY = 16
    GROUP = 17
    SYMTAB_SHNDX = 18
    LOPROC = 0x70000000
    ARM_ATTRIBUTES = 0x70000003
    HIPROC = 0x7fffffff
    LOUSER = 0x80000000
    HIUSER = 0xffffffff    


class SHF(IntFlag):
    WRITE = 0x1     # Writable
    ALLOC = 0x2     # Occupies memory during execution
    EXECINSTR = 0x4 # Executable
    MERGE = 0x10    # Might be merged
    STRINGS = 0x20 	# Contains null-terminated strings
    INFO_LINK = 0x40    # 'sh_info' contains SHT index
    LINK_ORDER = 0x80   # Preserve order after combining
    OS_NONCONFORMING = 0x100    # Non-standard OS specific handling required
    GROUP = 0x200   # Section is member of a group
    TLS = 0x400     # Section hold thread-local data
    MASKOS = 0x0FF00000 # OS-specific
    MASKPROC = 0xF0000000   # Processor-specific
    ORDERED = 0x4000000 # Special ordering requirement (Solaris)
    EXCLUDE = 0x8000000 # Section is excluded unless referenced or allocated (Solaris)     


class ELFSection(ELFItem, ELFString):
    def __init__(self, bitness=32, data=None):
        ELFItem.__init__(self, bitness)
        ELFString.__init__(self)
        self.format = "<2I4"+self.addr_format+"2I2"+self.addr_format
        if not data:
            data = b'\0'*calcsize(self.format)
            self.payload = b'' # a placeholder
        self.unpack(data)

    def unpack(self, data):
        self.unpack_from(data)

    def unpack_from(self, data, offset=0):
        self.name_idx, self.typ, self.flags, self.addr, self.offset, self.size, self.link, self.info, self.align, self.entsize  = unpack_from(self.format, data, offset)
        if offset: # operating on full ELF
            self.payload = data[self.offset:self.offset+self.size]
        self.name = '%08X' % (self.name_idx)

    def pack(self):
        return pack(self.format, self.name_idx, self.typ, self.flags, self.addr, self.offset, self.size, self.link, self.info, self.align, self.entsize)

    def __str__(self):
        return "{of:0{aw}X} {ad:0{aw}X} {sz:0{aw}X} {lk:08X} {nfo:08X} {al:0{aw}X} {es:0{aw}X} {nm:<20} {tp:<20} {fl}".format(
            aw=self.addr_str_width, of=self.offset, ad=self.addr, sz=self.size, lk=self.link, nfo=self.info, al=self.align, 
            es=self.entsize, nm=self.name, tp=str(SHT(self.typ)), fl=str(SHF(self.flags)))

    def has_data(self):
        return not self.typ in (SHT.NULL, SHT.NOBITS)

    def contains_va(self, va):
        return va>=self.addr and va<(self.addr+self.size)

    def contains_offset(self, offset):
        return offset>=self.offset and offset<(self.offset+self.size)


class ELFSectionTable(ELFTable):
    def __init__(self, bitness=32):
        super().__init__(ELFSection, bitness)

    def find_by_name(self, name):
        for sct in self.table:
            if sct.name==name:
                return sct
        return None

    def find_by_va(self, va):
        for sct in self.table:
            if sct.contains_va(va):
                return sct
        return None

    def find_by_offset(self, offset):
        for sct in self.table:
            if sct.contains_offset(offset):
                return sct
        return None
