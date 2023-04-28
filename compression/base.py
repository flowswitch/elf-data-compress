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

__all__ = ['BaseCompressionAlgo']

import os.path
import inspect
from struct import pack

class BaseCompressionAlgo:
	name = 'base'
	decompressor_aliases = {}
	def __init__(self, arch):
		self.arch = arch

	def compress(self, src):
		'''Data compression function
			param: src - data to be compressed
			returns: bytes - compressed data 
				or int - raw copy_table_entry.src value (for algos like FILL, outputting empty data + special .src)
				or None - this algo cannot compress this kind of data (i.e. FILL on nonequal bytes)
		'''
		raise NotImplementedError()

	def get_decompressor(self):
		return open(os.path.dirname(os.path.realpath(inspect.getfile(self.__class__)))+'/decompress/d_'+self.arch+'.bin', 'rb').read()

	def get_decompressor_align(self):
		return 1 # arch-dependent

	def get_data_align(self):
		return 1 # arch-dependent

	def pack_params(self, src, dst, size):
		'''Default param order: src, dst, size'''
		return pack('<III', src, dst, size)
