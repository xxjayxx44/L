/* $Id: haval_helper.c 218 2010-06-08 17:06:34Z tp $ */
/*
 * Helper code, included (three times !) by HAVAL implementation.
 *
 * TODO: try to merge this with md_helper.c.
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

#undef SPH_XCAT
#define SPH_XCAT(a, b)    SPH_XCAT_(a, b)
#undef SPH_XCAT_
#define SPH_XCAT_(a, b)   a ## b

/**
 * Process data bytes for HAVAL hashing. This function handles data in
 * chunks and ensures the context is updated correctly. If <code>len</code> 
 * is zero, this function does nothing.
 *
 * @param sc   Pointer to the HAVAL context
 * @param data Pointer to the input data
 * @param len  Length of the input data in bytes
 */
static void
#ifdef SPH_UPTR
SPH_XCAT(SPH_XCAT(haval, PASSES), _short)
#else
SPH_XCAT(haval, PASSES)
#endif
(sph_haval_context *sc, const void*data, size_t len)
{
    unsigned current = (unsigned)(SPH_64 ? (sc->count & 127U) : (sc->count_low & 127U));

    while (len > 0) {
        unsigned clen = 128U - current;
        if (clen > len) clen = (unsigned)len;

        memcpy(sc->buf + current, data, clen);
        data = (const unsigned char *)data + clen;
        current += clen;
        len -= clen;

        if (current == 128U) {
            DSTATE;
            IN_PREPARE(sc->buf);
            RSTATE;
            SPH_XCAT(CORE, PASSES)(INW);
            WSTATE;
            current = 0;
        }

        // Update the count
        if (SPH_64) {
            sc->count += clen;
        } else {
            sph_u32 clow = sc->count_low;
            sph_u32 clow2 = SPH_T32(clow + clen);
            sc->count_low = clow2;
            if (clow2 < clow) sc->count_high++;
        }
    }
}

#ifdef SPH_UPTR
/**
 * Process data bytes for HAVAL hashing when the length exceeds a threshold.
 *
 * @param sc   Pointer to the HAVAL context
 * @param data Pointer to the input data
 * @param len  Length of the input data in bytes
 */
static void
SPH_XCAT(haval, PASSES)(sph_haval_context *sc, const void*data, size_t len)
{
    unsigned current;
    size_t orig_len;

    DSTATE;

    // Handle short data length
    if (len < 256U) {
        SPH_XCAT(SPH_XCAT(haval, PASSES), _short)(sc, data, len);
        return;
    }

    current = (unsigned)(SPH_64 ? (sc->count & 127U) : (sc->count_low & 127U));

    // Process any existing data in the buffer
    if (current > 0) {
        unsigned clen = 128U - current;
        SPH_XCAT(SPH_XCAT(haval, PASSES), _short)(sc, data, clen);
        data = (const unsigned char *)data + clen;
        len -= clen;
    }

    // Check for unaligned data
#if !SPH_UNALIGNED
    if (((SPH_UPTR)data & 3U) != 0) {
        SPH_XCAT(SPH_XCAT(haval, PASSES), _short)(sc, data, len);
        return;
    }
#endif

    orig_len = len;
    RSTATE;

    // Process full blocks of
