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

__all__ = ["FillAlgo"]

from struct import pack
from ..base import BaseCompressionAlgo


class FillAlgo(BaseCompressionAlgo):
	name = 'fill'
	decompressor_aliases = { 'memset' : lambda src, dst, size : pack('<III', dst, src, size), 
								'__aeabi_memset' : lambda src, dst, size : pack('<III', dst, src, size) }

	def compress(self, src):
		if len(src)==0:
			return src

		val = src[0]
		for b in src:
			if b!=val:
				return None
		return val

	def get_decompressor_align(self):
		# TODO: arch-dependent
		# Cortex-M code w/o 32-bit fixed values wouldn't use literal pools, it is safe to align it to 2
		return 2 

	def get_data_align(self):
		# TODO: arch-dependent
		# All mem accesses are 8-bit here, no alignment requirements
		return 1 
	