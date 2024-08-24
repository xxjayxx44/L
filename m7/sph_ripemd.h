/* $Id: sph_ripemd.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * RIPEMD, RIPEMD-128 and RIPEMD-160 interface.
 *
 * RIPEMD was first described in: Research and Development in Advanced
 * Communication Technologies in Europe, "RIPE Integrity Primitives:
 * Final Report of RACE Integrity Primitives Evaluation (R1040)", RACE,
 * June 1992.
 *
 * A new, strengthened version, dubbed RIPEMD-160, was published in: H.
 * Dobbertin, A. Bosselaers, and B. Preneel, "RIPEMD-160, a strengthened
 * version of RIPEMD", Fast Software Encryption - FSE'96, LNCS 1039,
 * Springer (1996), pp. 71--82.
 *
 * This article describes both RIPEMD-160, with a 160-bit output, and a
 * reduced version called RIPEMD-128, which has a 128-bit output. RIPEMD-128
 * was meant as a "drop-in" replacement for any hash function with 128-bit
 * output, especially the original RIPEMD.
 *
 * @warning   Collisions, and an efficient method to build other collisions,
 * have been published for the original RIPEMD, which is thus considered as
 * cryptographically broken. It is also very rarely encountered, and there
 * seems to exist no free description or implementation of RIPEMD (except
 * the sphlib code, of course). As of january 2007, RIPEMD-128 and RIPEMD-160
 * seem as secure as their output length allows.
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
 * @file     sph_ripemd.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_RIPEMD_H__
#define SPH_RIPEMD_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * Output sizes for RIPEMD and its variants (in bits).
 */
#define SPH_SIZE_ripemd   128
#define SPH_SIZE_ripemd128   128
#define SPH_SIZE_ripemd160   160

/**
 * Common context structure for RIPEMD computations.
 * This structure contains the intermediate values and some data from the last
 * entered block. The context can be reused for another computation.
 */
#define RIPEMD_CONTEXT(name, size) \
typedef struct { \
    unsigned char buf[64]; /*first field for alignment*/ \
    sph_u32 val[(size) / 32]; \
    #if SPH_64 \
    sph_u64 count; \
    #else \
    sph_u32 count_high, count_low; \
    #endif \
} sph_##name##_context;

/

*Define contexts for RIPEMD, RIPEMD-128, and RIPEMD-160*

/
RIPEMD_CONTEXT(ripemd, SPH_SIZE_ripemd)
RIPEMD_CONTEXT(ripemd128, SPH_SIZE_ripemd128)
RIPEMD_CONTEXT(ripemd160, SPH_SIZE_ripemd160)

/**
 * Initialize a RIPEMD context. This process performs no memory allocation.
 *
 * @param cc   the RIPEMD context (pointer to a <code>sph_ripemd_context</code>)
 */
static inline void sph_ripemd_init(void *cc) {
    sph_ripemd_context *ctx = (sph_ripemd_context*)cc;
    memset(ctx, 0, sizeof(sph_ripemd_context));
}

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing).
 *
 * @param cc     the RIPEMD context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_ripemd(void *cc, const void*data, size_t len);

/**
 * Terminate the current RIPEMD computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to accommodate
 * the result (16 bytes). The context is automatically reinitialized.
 *
 * @param cc    the RIPEMD context
 * @param dst   the destination buffer
 */
void sph_ripemd_close(void *cc, void*dst);

/**
 * Apply the RIPEMD compression function on the provided data. The <code>msg</code>
 * parameter contains the 16 32-bit input blocks, as numerical values (hence after
 * the little-endian decoding). The <code>val</code> parameter contains the 4 32-bit
 * input blocks for the compression function; the output is written in place in this array.
 *
 * @param msg   the
