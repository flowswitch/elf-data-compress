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

__all__ = ['pad', 'ELFError', 'ELFItem', 'ELFString', 'ELFTable']

from struct import pack, calcsize
from enum import IntEnum
import logging


def pad(data, size, fill=0):
    '''Pad data to size using fill'''
    l = len(data)
    if l>size:
        raise ValueError("Source data is larger than padded size")
    if l<size:
        return data + pack('<B', fill)*(size-l)
    return data


class ELFError(Exception):
    pass

# templates

class ELFItem:
    def __init__(self, bitness=32):
        self.bitness = bitness
        self.addr_format = { 32: 'I', 64: 'Q' }[bitness]
        self.addr_str_width = bitness//4


class ELFString:
    def __init__(self):
        self.name_idx = 0
        self.name = ''

    def resolve_name(self, strtab):
        self.name = strtab[self.name_idx]


class ELFTable(ELFItem):
    def __init__(self, typ, bitness=32):
        self.typ = typ
        super().__init__(bitness)
        self.table = []

    def unpack(self, data):
        self.unpack_from(data)

    def unpack_from(self, data, offset=0, n_items=None, size=None):
        if n_items:
            for i in range(n_items):
                elem = self.typ(self.bitness)
                elem.unpack_from(data, offset)
                elem.index = i
                self.table.append(elem)
                offset += calcsize(elem.format)
            return

        if not size:
            size = len(data)
        ofs = 0
        while ofs<size:
            elem = self.typ(self.bitness)
            elem.unpack_from(data, offset+ofs)
            self.table.append(elem)
            ofs += calcsize(elem.format)

    def __getitem__(self, key):
        return self.table[key]

    def __len__(self):
        return len(self.table)

    def __str__(self) -> str:
        return '\n'.join([str(elem) for elem in self.table])

    def resolve_names(self, strtab):
        if not issubclass(self.typ, ELFString):
            raise ELFError("Attempt to resolve names of unnamed table items")

        for elem in self.table:
            elem.resolve_name(strtab)

