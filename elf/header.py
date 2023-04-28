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

__all__ = ['ELFHeader', 'ELF32Header', 'ELF64Header']

from struct import pack, unpack, unpack_from, calcsize
from enum import IntEnum
import logging

from .common import *


class ELFHeader(ELFItem):
    def __init__(self, data=None, bitness=32):
        super().__init__(bitness)
        self.format = '<3'+self.addr_format+'I6H'
        self.unpack(data)

    def unpack(self, data):
        if data[0:4]!=b'\x7FELF':
            raise ELFError("Not an ELF")

        (self.ident_class, self.ident_data, self.ident_version, self.ident_osabi, self.ident_abiversion,
            self.ident_pad, self.typ, self.machine, self.version) = unpack_from('<BBBBB7sHHI', data, 4)

        if self.ident_class==1:
            logging.info("ELF32")
            self.bitness=32
            self.addr_format = 'I'
        elif self.ident_class==2:
            logging.info("ELF64")
            self.bitness=64
            self.addr_format = 'Q'
        else:
            raise ELFError("Invalid ident_class "+str(self.ident_class))
        self.format = '<3'+self.addr_format+'I6H'

        (self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum,
            self.shentsize, self.shnum, self.shstrndx) = unpack_from(self.format, data, 0x18)

    def pack(self):
        return pack('<4s5B7s2HI', b'\x7FELF', self.ident_class, self.ident_data, self.ident_version, 
            self.ident_osabi, self.ident_abiversion, self.ident_pad, self.typ, self.machine, self.version) \
            + pack(self.format, self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx)


class ELF64Header(ELFHeader):
    def __init__(self, data=None):
        if not data:
            raise NotImplementedError("ELF creation is not supported yet")
        super().__init__(data)
         
    def unpack(self, data):
        super().unpack(data)
        if self.ident_class!=2:
            raise ELFError("Not a 64-bit ELF")
        (self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum,
            self.shentsize, self.shnum, self.shstrndx) = unpack_from('<QQQIHHHHHH', data, 0x18)

        if self.ehsize!=0x40 or self.phoff==0 or self.phentsize!=0x38 or self.phnum==0:
            raise ELFError("Incompatible ELF header")

    def pack(self):
        return super().pack()+pack('<QQQIHHHHHH', self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx)


class ELF32Header(ELFHeader):
    def __init__(self, data=None):
        if not data:
            raise NotImplementedError("ELF creation is not supported yet")
        super().__init__(data)

    def unpack(self, data):
        super().unpack(data)
        if self.ident_class!=1:
            raise ELFError("Not a 32-bit ELF")
        (self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum,
            self.shentsize, self.shnum, self.shstrndx) = unpack_from('<IIIIHHHHHH', data, 0x18)

        if self.ehsize!=0x34 or self.phoff==0 or self.phentsize!=0x20 or self.phnum==0:
            raise ELFError("Incompatible ELF header")

    def pack(self):
        return super().pack()+pack('<IIIIHHHHHH', self.entry, self.phoff, self.shoff, self.flags, self.ehsize, 
            self.phentsize, self.phnum, self.shentsize, self.shnum, self.shstrndx)
