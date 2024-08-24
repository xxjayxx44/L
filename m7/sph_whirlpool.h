/* $Id: sph_whirlpool.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * WHIRLPOOL interface.
 *
 * WHIRLPOOL knows three variants, dubbed "WHIRLPOOL-0" (original
 * version, published in 2000, studied by NESSIE), "WHIRLPOOL-1"
 * (first revision, 2001, with a new S-box) and "WHIRLPOOL" (current
 * version, 2003, with a new diffusion matrix, also described as "plain
 * WHIRLPOOL"). All three variants are implemented here.
 *
 * The original WHIRLPOOL (i.e. WHIRLPOOL-0) was published in: P. S. L.
 * M. Barreto, V. Rijmen, "The Whirlpool Hashing Function", First open
 * NESSIE Workshop, Leuven, Belgium, November 13--14, 2000.
 *
 * The current WHIRLPOOL specification and a reference implementation
 * can be found on the WHIRLPOOL web page:
 * http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html
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
 * @file     sph_whirlpool.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_WHIRLPOOL_H__
#define SPH_WHIRLPOOL_H__

#include <stddef.h>
#include "sph_types.h"

#if SPH_64

/**
 * Output size (in bits) for WHIRLPOOL and its variants.
 */
#define SPH_SIZE_whirlpool   512
#define SPH_SIZE_whirlpool0   512
#define SPH_SIZE_whirlpool1   512

/**
 * This structure is a context for WHIRLPOOL computations, containing
 * intermediate values and data from the last entered block. The context
 * can be reused for additional computations.
 */
typedef struct {
    unsigned char buf[64];    /*Buffer for input data*/
    sph_u64 state[8];        /*State variables*/
#if SPH_64
    sph_u64 count;           /*Bit count*/
#else
    sph_u32 count_high, count_low; /*Bit count (split)*/
#endif
} sph_whirlpool_context;

/**
 * Initialize a WHIRLPOOL context. This process performs no memory allocation.
 *
 * @param cc   Pointer to a <code>sph_whirlpool_context</code>
 */
static inline void sph_whirlpool_init(void *cc) {
    sph_whirlpool_context *ctx = (sph_whirlpool_context*)cc;
    memset(ctx, 0, sizeof(sph_whirlpool_context));  // Clear context
}

/**
 * Process data bytes. If <code>len</code> is zero, this function does nothing.
 *
 * @param cc     Pointer to the WHIRLPOOL context
 * @param data   Input data
 * @param len    Input data length (in bytes)
 */
void sph_whirlpool(void *cc, const void*data, size_t len);

/**
 * Terminate the current WHIRLPOOL computation and output the result into the
 * provided buffer. The destination buffer must accommodate the result (64 bytes).
 * The context is automatically reinitialized.
 *
 * @param cc    Pointer to the WHIRLPOOL context
 * @param dst   Destination buffer
 */
void sph_whirlpool_close(void *cc, void*dst);

/

*Define WHIRLPOOL-0 and WHIRLPOOL-1 contexts using the same structure*

/
typedef sph_whirlpool_context sph_whirlpool0_context;
typedef sph_whirlpool_context sph_whirlpool1_context;

/**
 * Initialize a WHIRLPOOL-0 context. Identical to <code>sph_whirlpool_init()</code>.
 *
 * @param cc   Pointer to a <code>sph_whirlpool0_context</code>
 */
static inline void sph_whirlpool0_init(void *cc) {
    sph_whirlpool_init(cc);
}

/**
 * Process data bytes for WHIRLPOOL-0. If <code>len</code> is zero, this function does nothing.
 *
 * @param cc     Pointer to the WHIRLPOOL-0 context
 * @param data   Input data
 * @param len    Input data length (in bytes)
 */
void sph_whirlpool0(void *cc, const void*data, size_t len);

/**
 * Terminate the current WHIRLPOOL-0 computation and output the result into the
 * provided buffer. The context is automatically reinitialized.
 *
 * @param cc    Pointer to the WHIRLPOOL-0 context
 * @param dst   Destination buffer
 */
void sph_whirlpool0_close(void *cc, void*dst);

/**
 * Initialize a WHIRLPOOL-1 context. Identical to <code>sph_whirlpool_init()</code>.
 *
 * @param cc   Pointer to a <code>sph_whirlpool1_context</code>
 */
