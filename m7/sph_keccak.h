/* $Id: sph_keccak.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * Keccak interface. This is the interface for Keccak with the
 * recommended parameters for SHA-3, with output lengths 224, 256,
 * 384 and 512 bits.
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
 * @file     sph_keccak.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */
#include "sph_types.h"
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#define SPH_SIZE_keccak224   224
#define SPH_SIZE_keccak256   256
#define SPH_SIZE_keccak384   384
#define SPH_SIZE_keccak512   512

typedef struct {
    unsigned char buf[144];    /*first field, for alignment*/
    size_t ptr, lim;
    union {
#if SPH_64
        uint64_t wide[25];
#endif
        uint32_t narrow[50];
    } u;
} sph_keccak_context;

typedef sph_keccak_context sph_keccak224_context;
typedef sph_keccak_context sph_keccak256_context;
typedef sph_keccak_context sph_keccak384_context;
typedef sph_keccak_context sph_keccak512_context;

static inline void sph_keccak_init(void *cc, size_t buffer_size) {
    sph_keccak_context *ctx = (sph_keccak_context*)cc;
    memset(ctx, 0, sizeof(sph_keccak_context));
    ctx->lim = buffer_size;
    ctx->ptr = 0;
}

static inline void sph_keccak_update(void *cc, const void*data, size_t len) {
    sph_keccak_context *ctx = (sph_keccak_context*)cc;
    if (len == 0) return;

    size_t remaining = ctx->lim - ctx->ptr;
    if (len < remaining) {
        memcpy(ctx->buf + ctx->ptr, data, len);
        ctx->ptr += len;
    } else {
        memcpy(ctx->buf + ctx->ptr, data, remaining);
        // Process the full block
        // Call your processing function here
        ctx->ptr = 0; // Reset buffer pointer
        // Continue processing the rest of the data
        const uint8_t *ptr = (const uint8_t*)data + remaining;
        len -= remaining;
        while (len >= ctx->lim) {
            // Process the full block
            // Call your processing function here
            ptr += ctx->lim;
            len -= ctx->lim;
        }
        // Remaining data
        memcpy(ctx->buf, ptr, len);
        ctx->ptr = len;
    }
}

static inline void sph_keccak_close(void *cc, void*dst, size_t out_size) {
    sph_keccak_context *ctx = (sph_keccak_context*)cc;
    // Finalize the hash
    // Call your finalization function here
    memset(ctx, 0, sizeof(sph_keccak_context)); // Reset context
}

void sph_keccak224_init(void *cc) { sph_keccak_init(cc, 144); }
void sph_keccak224(void *cc, const void*data, size_t len) { sph_keccak_update(cc, data, len); }
void sph_keccak224_close(void *cc, void*dst) {

