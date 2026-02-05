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

__all__ = ['ELF']

from struct import pack, unpack, unpack_from
from enum import IntEnum
import logging

from .common import *
from .header import *
from .segment import *
from .section import *
from .symbol_table import *
from .string_table import *


class ELF:
    def __init__(self, data=None, readonly=True):
        if not data:
            # TODO: empty ELF creation
            raise NotImplementedError("ELF creation is not supported")
        self.readonly = readonly
        self.unpack(data)

    @classmethod
    def from_file(cls, path, readonly=True):
        return cls(open(path, 'rb').read(), readonly)

    def unpack(self, data):
        # if data[0:4]!=b'\x7FELF':
        #     raise ELFError("Not an ELF")

        # ident_class = data[4]
        # if ident_class==1:
        #     logging.info("ELF32")
        #     self.header = ELF32Header(data)
        #     self.bitness=32
        # elif ident_class==2:
        #     logging.info("ELF64")
        #     self.header = ELF64Header(data)
        #     self.bitness=64
        # else:
        #     raise ELFError("Invalid ident_class "+str(ident_class))
        self.header = ELFHeader(data)

        if not self.readonly and self.header.ehsize!=self.header.phoff:
            raise ELFError("Incompatible writable ELF layout: PHT is not next to the header")

        if not self.readonly and self.header.shoff and self.header.shnum and (self.header.shoff + self.header.shnum*self.header.shentsize)!=len(data):
            raise ELFError("Incompatible writable ELF layout: SHT is not at the end")

        logging.debug("%d segments", self.header.phnum)
        logging.debug("%d sections", self.header.shnum)

        self.segments = ELFSegmentTable(self.header.bitness)
        self.segments.unpack_from(data, self.header.phoff, n_items=self.header.phnum)

        self.sections = ELFSectionTable(self.header.bitness)
        self.sections.unpack_from(data, self.header.shoff, n_items=self.header.shnum)

        # string table is accessible now, resolve section names
        if self.header.shstrndx:
            self.shstrtab = ELFStringTable(self.sections[self.header.shstrndx])
            self.sections.resolve_names(self.shstrtab)
        else:
            self.shstrtab = None

        strtab = self.sections.find_by_name('.strtab')
        symtab = self.sections.find_by_name('.symtab')
        self.symbols = ELFSymbolTable(self.header.bitness)
        if symtab:
            if not strtab:
                raise ELFError("Found symbol table without string table")
            logging.info("Parsing symbols...")
            self.symbols.unpack_from_section(data, symtab)
            self.strings = ELFStringTable(strtab)
            self.symbols.resolve_names(self.strings)

    def pack_header(self):
        return self.header.pack()+b''.join([s.pack() for s in self.segments])

    def pack_sht(self):
        return b''.join([s.pack() for s in self.sections])

    def pack(self):
        # determine image size needed to fit all segments/sections
        # we can't just append all segments sequentially, they can be unordered
        self.image_size = 0
        for s in self.segments:
            if s.filesz:
                self.image_size = max(self.image_size, s.offset+s.filesz)
        for s in self.sections:
            if s.has_data():
                self.image_size = max(self.image_size, s.offset+s.size)
        if self.sections:
            # align and place the SHT
            self.image_size = ((self.image_size-1) | 3)+1
            self.header.shoff = self.image_size
            self.image_size += self.header.shentsize*len(self.sections)
        logging.info("New image size: %X" % (self.image_size))
        out = bytearray(self.image_size)

        for s in self.segments:
            out[s.offset:s.offset+s.filesz] = s.payload[0:s.filesz]

        for s in self.sections:
            if s.has_data():
                out[s.offset:s.offset+s.size] = s.payload[0:s.size]

        self.header.phnum = len(self.segments)
        self.header.shnum = len(self.sections)
        hdr = self.pack_header()
        out[0:len(hdr)] = hdr

        sht = self.pack_sht()
        out[self.header.shoff:self.header.shoff+len(sht)] = sht

        return out

    ############# section functions ################

    def find_section_by_name(self, name: str) -> ELFSection:
        return self.sections.find_by_name(name)

    def find_section_by_va(self, va: int) -> ELFSection:
        return self.sections.find_by_va(va)

    def find_section_by_offset(self, offset: int) -> ELFSection:
        return self.sections.find_by_offset(offset)

    ############# segment functions ################

    def find_segment_by_va(self, va: int) -> ELFSegment:
        return self.segments.find_by_va(va)

    def find_segment_by_pa(self, pa: int) -> ELFSegment:
        return self.segments.find_by_pa(pa)

    def find_segment_by_offset(self, offset: int) -> ELFSegment:
        return self.segments.find_by_offset(offset)

    ############ symbol functions #################

    def find_symbol(self, name: str=None, value: int=None, size: int=None, typ: STT=None, bind: STB=None, shndx: int=None) -> ELFSymbol:
        return self.symbols.find(name, value, size, typ, bind, shndx)
        
    ############ raw content access functions #####

    def va_to_offset(self, va: int) -> int:
        '''Map virtual address to file offset'''
        # try in segments
        seg = self.find_segment_by_va(va)
        if seg:
            return seg.offset+va-seg.vaddr
        # try in sections
        sct = self.find_section_by_va(va)
        if sct:
            return sct.offset+va-sct.addr
        # not found
        return None

    def read_from_va(self, va: int, size: int) -> bytes:
        if not size:
            return b''
        # try segments
        seg = self.find_segment_by_va(va)
        if seg:
            if (va+size) > (seg.vaddr+seg.memsz):
                raise IndexError("Read @%X[%X] is out of bounds or crosses segment boundaries" % (va, size))
            start = va-seg.vaddr
            end = start+size
            # a segment can have memsz>filesz (zero-padded at load time) 
            # and we can hit the non-present tail area between filesz and memsz
            if start >= seg.filesz: # entire read range is in the tail area
                return b'\0'*size
            if end > seg.filesz: # partially in the tail area
                return seg.payload[start:seg.filesz]+b'\0'*(end-seg.filesz)
            return seg.payload[va-seg.vaddr:va-seg.vaddr+size]
        # try sections
        sct = self.find_section_by_va(va)
        if sct:
            if (va+size) > (sct.addr+sct.size):
                raise IndexError("Read @%X[%X] is out of bounds or crosses section boundaries" % (va, size))
            return sct.payload[va-sct.addr:va-sct.addr+size]
        raise IndexError("Read @%X[%X] does not belong to any segment/section" % (va, size))

    def write_to_va(self, va: int, data):
        if not data:
            return
        data = bytes(data)
        size = len(data)
        # try segments
        seg = self.find_segment_by_va(va)
        result = False
        if seg:
            if (va+size) > (seg.vaddr+seg.filesz):
                raise IndexError("Write @%X[%X] is out of bounds or crosses segment boundaries" % (va, size))
            start = va-seg.vaddr
            end = start+size
            seg.payload = seg.payload[0:start]+data+seg.payload[end:]
            result = True
            # do not return, try sections too, the address range can be duplicated there
        # try sections
        sct = self.find_section_by_va(va)
        if sct:
            if (va+size) > (sct.addr+sct.size):
                raise IndexError("Write @%X[%X] is out of bounds or crosses section boundaries" % (va, size))
            start = va-sct.addr
            end = start+size
            sct.payload = sct.payload[0:start]+data+sct.payload[end:]
            result = True
        if not result:
            raise IndexError("Write @%X[%X] does not belong to any segment/section" % (va, size))
