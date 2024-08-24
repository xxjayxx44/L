/* $Id: md_helper.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * This file contains some functions which implement the external data
 * handling and padding for Merkle-Damgard hash functions which follow
 * the conventions set out by MD4 (little-endian) or SHA-1 (big-endian).
 *
 * API: this file is meant to be included, not compiled as a stand-alone
 * file. Some macros must be defined:
 *   RFUN   name for the round function
 *   HASH   "short name" for the hash function
 *   BE32   defined for big-endian, 32-bit based (e.g. SHA-1)
 *   LE32   defined for little-endian, 32-bit based (e.g. MD5)
 *   BE64   defined for big-endian, 64-bit based (e.g. SHA-512)
 *   LE64   defined for little-endian, 64-bit based (no example yet)
 *   PW01   if defined, append 0x01 instead of 0x80 (for Tiger)
 *   BLEN   if defined, length of a message block (in bytes)
 *   PLW1   if defined, length is defined on one 64-bit word only (for Tiger)
 *   PLW4   if defined, length is defined on four 64-bit words (for WHIRLPOOL)
 *   SVAL   if defined, reference to the context state information
 *
 * BLEN is used when a message block is not 16 (32-bit or 64-bit) words:
 * this is used for instance for Tiger, which works on 64-bit words but
 * uses 512-bit message blocks (eight 64-bit words). PLW1 and PLW4 are
 * ignored if 32-bit words are used; if 64-bit words are used and PLW1 is
 * set, then only one word (64 bits) will be used to encode the input
 * message length (in bits), otherwise two words will be used (as in
 * SHA-384 and SHA-512). If 64-bit words are used and PLW4 is defined (but
 * not PLW1), four 64-bit words will be used to encode the message length
 * (in bits). Note that regardless of those settings, only 64-bit message
 * lengths are supported (in bits): messages longer than 2 Exabytes will be
 * improperly hashed (this is unlikely to happen soon: 2 Exabytes is about
 * 2 millions Terabytes, which is huge).
 *
 * If CLOSE_ONLY is defined, then this file defines only the sph_XXX_close()
 * function. This is used for Tiger2, which is identical to Tiger except
 * when it comes to the padding (Tiger2 uses the standard 0x80 byte instead
 * of the 0x01 from original Tiger).
 *
 * The RFUN function is invoked with two arguments, the first pointing to
 * aligned data (as a "const void *"), the second being state information
 * from the context structure. By default, this state information is the
 * "val" field from the context, and this field is assumed to be an array
 * of words ("sph_u32" or "sph_u64", depending on BE32/LE32/BE64/LE64).
 * from the context structure. The "val" field can have any type, except
 * for the output encoding which assumes that it is an array of "sph_u32"
 * values. By defining NO_OUTPUT, this last step is deactivated; the
 * includer code is then responsible for writing out the hash result. When
 * NO_OUTPUT is defined, the third parameter to the "close()" function is
 * ignored.
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



#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#undef SPH_XCAT
#define SPH_XCAT(a, b)     SPH_XCAT_(a, b)
#undef SPH_XCAT_
#define SPH_XCAT_(a, b)    a ## b

#undef SPH_BLEN
#undef SPH_WLEN
#if defined BE64 || defined LE64
#define SPH_BLEN    128U
#define SPH_WLEN      8U
#else
#define SPH_BLEN     64U
#define SPH_WLEN      4U
#endif

#ifdef BLEN
#undef SPH_BLEN
#define SPH_BLEN    BLEN
#endif

#undef SPH_MAXPAD
#if defined PLW1
#define SPH_MAXPAD   (SPH_BLEN - SPH_WLEN)
#elif defined PLW4
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 2))
#else
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 1))
#endif

#undef SPH_VAL
#undef SPH_NO_OUTPUT
#ifdef SVAL
#define SPH_VAL         SVAL
#define SPH_NO_OUTPUT   1
#else
#define SPH_VAL   sc->val
#endif

#ifndef CLOSE_ONLY

#ifdef SPH_UPTR
static void HASH_short(void *cc, const void*data, size_t len)
#else
void sph_HASH(void *cc, const void*data, size_t len)
#endif
{
    sph_HASH_context *sc = cc;
    unsigned current;

#if SPH_64
    current = (unsigned)sc->count & (SPH_BLEN - 1U);
#else
    current = (unsigned)sc->count_low & (SPH_BLEN - 1U);
#endif
    while (len > 0) {
        unsigned clen = SPH_BLEN - current;
        if (clen > len) clen = len;
        memcpy(sc->buf + current, data, clen);
        data = (const unsigned char *)data + clen;
        current += clen;
        len -= clen;
        if (current == SPH_BLEN) {
            RFUN(sc->buf, SPH_VAL);
            current = 0;
        }
#if SPH_64
        sc->count += clen;
#else
        sph_u32 clow = sc->count_low;
        sph_u32 clow2 = SPH_T32(clow + clen);
        sc->count_low = clow2;
        if (clow2 < clow) sc->count_high++;
#endif
    }
}

#ifdef SPH_UPTR
void sph_HASH(void *cc, const void*data, size_t len)
{
    sph_HASH
