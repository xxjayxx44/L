/* $Id: haval.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * HAVAL implementation.
 *
 * The HAVAL reference paper is of questionable clarity with regards to
 * some details such as endianness of bits within a byte, bytes within
 * a 32-bit word, or the actual ordering of words within a stream of
 * words. This implementation has been made compatible with the reference
 * implementation available on: http://labs.calyptix.com/haval.php
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */


#include <stddef.h>
#include <string.h>
#include "sph_haval.h"

#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_HAVAL
#define SPH_SMALL_FOOTPRINT_HAVAL 1
#endif

#define F1(x6, x5, x4, x3, x2, x1, x0) \
    (((x1) & ((x0) ^ (x4))) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ (x0))

#define F2(x6, x5, x4, x3, x2, x1, x0) \
    (((x2) & (((x1) & ~(x3)) ^ ((x4) & (x5)) ^ (x6) ^ (x0))) \
    ^ ((x4) & ((x1) ^ (x5))) ^ ((x3) & (x5)) ^ (x0))

#define F3(x6, x5, x4, x3, x2, x1, x0) \
    (((x3) & (((x1) & (x2)) ^ (x6) ^ (x0))) \
    ^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ (x0))

#define F4(x6, x5, x4, x3, x2, x1, x0) \
    (((x3) & (((x1) & (x2)) ^ ((x4) | (x6)) ^ (x5))) \
    ^ ((x4) & ((~(x2) & (x5)) ^ (x1) ^ (x6) ^ (x0))) \
    ^ ((x2) & (x6)) ^ (x0))

#define F5(x6, x5, x4, x3, x2, x1, x0) \
    (((x0) & ~(((x1) & (x2) & (x3)) ^ (x5))) \
    ^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)))

#define FP3_1(x6, x5, x4, x3, x2, x1, x0) F1(x1, x0, x3, x5, x6, x2, x4)
#define FP3_2(x6, x5, x4, x3, x2, x1, x0) F2(x4, x2, x1, x0, x5, x3, x6)
#define FP3_3
