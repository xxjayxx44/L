/* $Id: sph_sha2.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * SHA-224, SHA-256, SHA-384 and SHA-512 interface.
 *
 * SHA-256 has been published in FIPS 180-2, now amended with a change
 * notice to include SHA-224 as well (which is a simple variation on
 * SHA-256). SHA-384 and SHA-512 are also defined in FIPS 180-2. FIPS
 * standards can be found at:
 *    http://csrc.nist.gov/publications/fips/
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
 * @file     sph_sha2.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_SHA512_H__
#define SPH_SHA512_H__

#include <stddef.h>
#include "sph_types.h"

/**
 * SHA-512 context structure, which contains the intermediate values and 
 * data for the last processed block. This context can be reused for 
 * subsequent computations.
 */
typedef struct {
    sph_u64 state[8];       /*State variables*/
    unsigned char buf[128]; /

*Buffer for input data (aligned for performance)*

/
#if SPH_64
    sph_u64 count;          /*Bit count*/
#else
    sph_u32 count_high, count_low; /*Split bit count for 32-bit systems*/
#endif
} sph_sha512_context;

/**
 * Initialize a SHA-512 context. This process performs no memory allocation.
 *
 * @param cc   Pointer to a <code>sph_sha512_context</code>
 */
static inline void sph_sha512_init(void *cc) {
    sph_sha512_context *ctx = (sph_sha512_context*)cc;
    memset(ctx, 0, sizeof(sph_sha512_context)); // Clear context
    // Additional initialization steps can be added here if necessary
}

/**
 * Process data bytes for SHA-512. If <code>len</code> is zero, this function does nothing.
 *
 * @param cc     Pointer to the SHA-512 context
 * @param data   Input data
 * @param len    Input data length (in bytes)
 */
void sph_sha512(void *cc, const void*data, size_t len);

/**
 * Terminate the current SHA-512 computation and output the result into 
 * the provided buffer (64 bytes required). The context is automatically 
 * reinitialized.
 *
 * @param cc    Pointer to the SHA-512 context
 * @param dst   Destination buffer
 */
void sph_sha512_close(void *cc, void*dst);

/**
 * Add a few additional bits (0 to 7) to the current computation, then 
 * terminate it and output the result in the provided buffer (64 bytes required). 
 * The context is automatically reinitialized.
 *
 * @param cc    Pointer to the SHA-512 context
 * @param ub    The additional bits
 * @param n     The number of additional bits (0 to 7)
 * @param dst   Destination buffer
 */
void sph_sha512_addbits_and_close(void *cc, unsigned ub, unsigned n, void*dst);

/**
 * Apply the SHA-512 compression function. This function operates on 
 * the input message block and updates the state.
 *
 * @param msg   The message block (16 values)
 * @param val   The function's input and output (512-bit)
 */
void sph_sha512_comp(const sph_u64 msg[16], sph_u64 val[8]);

// Define SHA-512 as an alias for SHA-384, since they share the same implementation.
#define sph_sha512   sph_sha384

#endif // SPH_SHA512_H__
