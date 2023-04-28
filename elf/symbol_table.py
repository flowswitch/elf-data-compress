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

__all__ = ['ELFSymbol', 'ELFSymbolTable', 'STB', 'STT']

from struct import pack, unpack, unpack_from, calcsize
from enum import IntEnum, IntFlag

from .common import *


# Symbol binding types
class STB(IntEnum):
    LOCAL = 0
    GLOBAL = 1
    WEAK = 2
    LOPROC = 13
    HIPROC = 15


# Symbol types
class STT(IntEnum):
    NOTYPE = 0
    OBJECT = 1
    FUNC = 2
    SECTION = 3
    FILE = 4
    LOPROC = 13
    HIPROC = 15    


class ELFSymbol(ELFItem, ELFString):
    def __init__(self, bitness=32, data=None):
        ELFItem.__init__(self, bitness)
        ELFString.__init__(self)
        self.format = "<I"+self.addr_format+"IBBH"
        if not data:
            data = b'\0'*calcsize(self.format)
        self.unpack(data)

    def unpack(self, data):
        self.unpack_from(data)

    def unpack_from(self, data, offset=0):
        self.name_idx, self.value, self.size, info, self.other, self.shndx = unpack_from(self.format, data, offset)
        self.bind = info>>4
        self.typ = info & 0x0F

    def pack(self):
        info = (self.bind<<4) | self.typ
        return pack(self.format, self.name_idx, self.value, self.size, info, self.other, self.shndx)

    def __str__(self):
        return "{val:0{aw}X} [{sz:0{aw}X}] {si:08X} {stb:16} {stt:16} {nm}".format(aw=self.addr_str_width, 
            val=self.value, sz=self.size, si=self.shndx, nm=self.name, stb=str(STB(self.bind)), stt=str(STT(self.typ)))


class ELFSymbolTable(ELFTable):
    def __init__(self, bitness=32):
        super().__init__(ELFSymbol, bitness)

    def unpack_from_section(self, data, section):
        return super().unpack_from(data, section.offset, size=section.size)

    def find(self, name: str=None, value: int=None, size: int=None, typ: STT=None, bind: STB=None, shndx: int=None) -> ELFSymbol:
        for sym in self.table:
            if (name is None or name==sym.name) \
                and (value is None or value==sym.value) \
                and (size is None or size==sym.size) \
                and (typ is None or typ==sym.typ) \
                and (bind is None or bind==sym.bind) \
                and (shndx is None or shndx==sym.shndx):
                return sym
        return None
