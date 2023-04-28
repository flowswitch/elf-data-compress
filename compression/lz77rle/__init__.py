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

__all__ = ["LZ77RLEAlgo"]

from struct import pack
from ..base import BaseCompressionAlgo

MIN_COPY = 3

class LZ77RLEAlgo(BaseCompressionAlgo):
    name = 'lz77rle'
    decompressor_aliases = { '__scatterload_lz77rle': lambda src, dst, size : pack('<III', src, dst, size) }

    def compress(self, src):
        dst = b''
        si = 0
        size = len(src)
        lit_start = 0
        lit_len = 0
        while si<size:
            #print("%X: " % (si), end='')
            # count zeroes
            for i in range(si, min(si+255, size)):
                if src[i]!=0:
                    break
            else:
                i = min(si+255, size)
            nzero = i - si
            if nzero==min(255, size-si): #best case, no need to look for matches
                ncopy = 0
            else:
                # look for matches
                ncopy=0
                copy_ofs = 0
                for ofs in range(max(si-1, 0), max(si-255, 0), -1):
                    for i in range(ofs, min(ofs+255, size)):
                        if (si+i-ofs)>=size:
                            break
                        if src[i]!=src[si+i-ofs]:
                            #print('@%X %02X!=%02X @%X' % (i, src[i], src[si+i-ofs], si+i-ofs))
                            break
                    l = i-ofs
                    if l>ncopy:
                        ncopy = l
                        copy_ofs = ofs
                if ncopy<MIN_COPY:
                    ncopy = 0

            if nzero==0 and ncopy==0:
                lit_len += 1
                si += 1
                if lit_len<254 and si<size:
                    #print('lit %02X' % (src[si-1]))
                    continue

            # output
            hdr = 0
            tail = b''
            #print("%X: nlit=%X, " % (len(dst), lit_len), end='')
            if lit_len<=6:
                hdr |= (lit_len+1)
                extra = b''
            else:
                extra = pack('B', lit_len+1)
            #print('nz=%X, nc=%X, ' % (nzero, ncopy), end='')
            if (nzero+1)>ncopy:
                # zerofill is better
                #print('nzero=%X' % (nzero))
                si += nzero           
                if nzero>0 and nzero<=15:
                    hdr |= nzero<<4
                else:
                    extra += pack('B', nzero)
            else:
                dist = si-copy_ofs
                #print('distcopy @%X(-%X)[%X]' % (copy_ofs, dist, ncopy))
                si += ncopy
                hdr |= 8 # DISTCOPY flag
                ncopy -= 2
                if ncopy<=15:
                    hdr |= ncopy<<4
                else:
                    extra += pack('B', ncopy)
                tail = pack('B', dist)
            dst += pack('B', hdr)+extra+src[lit_start:lit_start+lit_len]+tail
            lit_start = si
            lit_len = 0

        return dst

    def get_decompressor_align(self):
        # TODO: arch-dependent
        # Cortex-M code w/o 32-bit fixed values wouldn't use literal pools, it is safe to align it to 2
        return 2 

    def get_data_align(self):
        # TODO: arch-dependent
        # All mem accesses are 8-bit here, no alignment requirements
        return 1 
