/*
 * Copyright (c) 2023, FlowSwitch <flowswitch@mail.ru>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>

typedef unsigned char u8;

void __scatterload_algo(const u8 *src, u8 *dst, size_t size)
{
	u8 *dst_end = &dst[size];
  	while(dst<dst_end)
  	{
    	u8 hdr = *src++;
    	u8 nlit = hdr & 7;
    	if (!nlit)
    	{
      		nlit = *src++;
    	}
    	u8 ncomp = hdr >> 4;
    	if (!ncomp)
    	{
      		ncomp = *src++;
    	}
    	while (--nlit) //1-based
    	{
      		*dst++ = *src++;
    	}
    	if (hdr & 8)
    	{
      		u8 dist = *src++;
      		u8 *cpy_src = &dst[-dist];
			ncomp += 2;
      		while (--ncomp >= 0)
      		{
        		*dst++ = *cpy_src++;
      		}
    	}
    	else
    	{
      		while (--ncomp >= 0)
        	*dst++ = 0;
    	}
  	}
}