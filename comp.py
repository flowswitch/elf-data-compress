#!/usr/bin/env python3

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


from sys import argv, exit
from struct import pack, unpack
import logging

from numpy import add

import elf
from compression import algos


if len(argv)!=4:
	exit("Usage: "+argv[0]+" <arch> <infile.elf> <outfile.elf>")


class CompressedData:
	def __init__(self, algo, src, dst: int, size: int) -> None:
		self.algo = algo
		self.src = src
		self.dst = dst
		self.size = size


class DecompressorInstance:
	def __init__(self, image=b'', address=None, align=1, pack_params=lambda src, dst, size : pack('<III', src, dst, size)):
		self.image = image
		self.address = address
		self.pack_params = pack_params
		self.align = align


class DecompressorManager:
	def __init__(self, binary):
		self.binary = binary
		self.decompressors = {}
		self.image = b''

	def GetDecompressorCost(self, algo):
		if algo.name in self.decompressors:
			return 0 # already "paid"
		for fn_name in algo.decompressor_aliases:
			sym = self.binary.find_symbol(fn_name)
			if sym:
				return 0 # in the app code already
		else:
			return len(algo.get_decompressor())

	def add(self, algo):
		if algo.name in self.decompressors:
			return
		decomp = DecompressorInstance()
		for fn_name in algo.decompressor_aliases:
			sym = self.binary.find_symbol(fn_name)
			if sym:
				decomp.address = sym.value
				decomp.pack_params = algo.decompressor_aliases[fn_name]
				logging.debug('Found builtin func '+fn_name+' at '+hex(sym.value)+' for algo '+algo.name)
				break
		else:
			decomp.image = algo.get_decompressor()
			decomp.align = algo.get_decompressor_align()
		self.decompressors[algo.name] = decomp			
		
	def build(self, address):
		self.image = b''
		for decomp in self.decompressors:
			if not self.decompressors[decomp].address:
				if misalign:=(address % self.decompressors[decomp].align):
					align = self.decompressors[decomp].align-misalign
					address += align
					self.image += b'\0'*align
				self.decompressors[decomp].address = address
				self.image += self.decompressors[decomp].image
				address += len(self.decompressors[decomp].image)
		return self.image

	def make_table_entry(self, algo, src, dst, size):
		return self.decompressors[algo.name].pack_params(src, dst, size)+pack('<I', self.decompressors[algo.name].address)


logging.basicConfig(level=logging.DEBUG, format='%(message)s')		
arch = argv[1]

binary = elf.ELF.from_file(argv[2], readonly=False)
if binary.header.bitness!=32:
	exit('Unsupported ELF bitness %d' % (binary.bitness))

table_sym = binary.find_symbol('__data_init_table')
if not table_sym:
	exit('ERROR: No __data_init_table symbol found. Please check your .ld script.')
table_p = table_sym.value
logging.debug('__data_init_table: '+hex(table_p))
if table_p & 3:
	exit('table_p is not aligned to 4 !')

idata = binary.sections[table_sym.shndx]
logging.debug('.idata: '+hex(idata.addr)+' ['+hex(idata.size)+']')
if table_p!=(idata.addr):
	exit('.idata section doesn\'t start at table_p !')

n_entries = unpack('<I', binary.read_from_va(table_p, 4))[0]
logging.info(str(n_entries)+' sections to initialize')

logging.info("Compressing sections...")
dm = DecompressorManager(binary)
srcdata = [None] * n_entries
out_n_entries = 0
for idx in range(n_entries):
	src, dst, size, pfn = unpack('<4I', binary.read_from_va(table_p+4+idx*16, 16))
	logging.info("%2d: %08X -> %08X [%08X]" % (idx, src, dst, size))
	if not size:
		continue
	out_n_entries += 1
	best_size = 0xFFFFFFFF
	best_algo = None
	best_data = b''
	raw_data = binary.read_from_va(dst, size)
	for algo in algos:
		logging.debug("\tTrying "+algo.name)
		comper = algo(arch)
		comp_data = comper.compress(raw_data)
		if comp_data is None: # this algo can't compress this kind of data
			logging.debug("\t\tn/a")
			continue
		if isinstance(comp_data, int): # this algo doesn't produce any data, only the src int value
			comp_size = 0
		else:
			comp_size = len(comp_data)
		dc_size = dm.GetDecompressorCost(comper)
		sz = comp_size+dc_size
		logging.debug("\t\t%X -> %X+%X=%X" % (len(raw_data), comp_size, dc_size, sz))
		if sz<best_size:
			best_size = sz
			best_algo = comper
			best_data = comp_data
		if sz==0: # nothing can be better
			break
	if best_algo is None:
		exit("Can't compress !")
	logging.info("\tBest algo: %s (%X -> %X)" % (best_algo.name, len(raw_data), best_size))
	dm.add(best_algo)
	srcdata[idx] = CompressedData(best_algo, best_data, dst, size)
	sct = binary.find_section_by_va(dst)
	# Mark section to be excluded from objcopy bin/hex generation
	if sct.typ==elf.section.SHT.PROGBITS:
		binary.sections[sct.index].typ = elf.section.SHT.NOBITS

fn_addr = table_p+4+out_n_entries*16
decomp_code = dm.build(fn_addr)
data_addr = fn_addr+len(decomp_code)

logging.info("Building .idata...")
# __table_p:
# dd n_entries
# table {dd src, dd dst, dd size, dd pfn }[2]
# unp[]
# clr[]
# comp_data[]
tbl = pack('<I', out_n_entries)
comp_data = b''
for idx in range(n_entries):
	if not srcdata[idx]:
		continue
	if isinstance(srcdata[idx].src, int):
		src = srcdata[idx].src
		src_size = 0
	else:
		src = data_addr
		src_size = len(srcdata[idx].src)
		comp_data += srcdata[idx].src
	tbl += dm.make_table_entry(srcdata[idx].algo, src, srcdata[idx].dst, srcdata[idx].size)
	data_addr += src_size

image = tbl
image += decomp_code
image += comp_data
if len(image)>idata.size:
	exit("ERROR: Can't fit the resulting init image of size %X into .idata section of size %X" % (len(image), idata.size))
binary.write_to_va(table_p, image)

logging.info("Shrinking .idata...")
binary.sections[table_sym.shndx].size = len(image)

logging.info("Saving...")
open(argv[3], 'wb').write(binary.pack())

logging.info("Done")
exit(0)
