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

__all__ = ["PackBitsAlgo"]

from struct import pack
from ..base import BaseCompressionAlgo

MIN_RLE = 2
MAX_RLE = 128
MAX_LIT = 128

class PackBitsAlgo(BaseCompressionAlgo):
	name = 'packbits'
	decompressor_aliases = { '__scatterload_packbits': lambda src, dst, size : pack('<III', src, dst, size) }

	def compress(self, src):
		dst = b''
		si = 0
		size = len(src)
		lit_start = 0
		lit_len = 0

		def out_lit():
			if lit_len:
				print("out LIT")
				dst += pack('<B', lit_len-1)+src[lit_start:si]
			lit_start = si
			lit_len = 0

		while si<size:
			data = src[si]
			#print("%X: %02X " % (si, data), end='')
			# count repeats
			for i in range(si, min(si+MAX_RLE, size)):
				if src[i]!=data:
					break
			else:
				i = min(si+MAX_RLE, size)
			nrle = i - si
			#print("n_rle: %X " % (nrle), end='')
			if nrle>=MIN_RLE:
				if lit_len:
					#print("out LIT")
					dst += pack('<B', lit_len-1)+src[lit_start:si]
				#print("out RLE")
				si += nrle
				dst += pack("<BB", (-nrle) & 0xFF, data)
				lit_start = si
				lit_len = 0
			else:
				si += 1
				lit_len += 1
				if lit_len==MAX_LIT:
					if lit_len:
						#print("out LIT")
						dst += pack('<B', lit_len-1)+src[lit_start:si]
					lit_start = si
					lit_len = 0
				#else:
				#	print("")
		if lit_len:
			#print("out LIT")
			dst += pack('<B', lit_len-1)+src[lit_start:si]
		lit_start = si
		lit_len = 0

		return dst

	def decompress(self, src):
		'''For testing'''
		dst = b''
		size = len(src)
		si = 0
		while si<size:
			hdr = src[si]
			si += 1
			if hdr<128:
				dst += src[si:si+hdr+1]
				si += hdr+1
			else:
				dst += src[si:si+1]*(256-hdr)
				si += 1
		return dst

	def get_decompressor_align(self):
		# TODO: arch-dependent
		# Cortex-M code w/o 32-bit fixed values wouldn't use literal pools, it is safe to align it to 2
		return 2 

	def get_data_align(self):
		# TODO: arch-dependent
		# All mem accesses are 8-bit here, no alignment requirements
		return 1 
