/*
 * Copyright 2012 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */

#ifndef WIN32
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <libbase58.h>

#include <blkmaker.h>

#include "private.h"

bool _blkmk_b58tobin(void *bin, size_t binsz, const char *b58, size_t b58sz) {
	return b58tobin(bin, &binsz, b58, b58sz);
}

int _blkmk_b58check(void *bin, size_t binsz, const char *base58str) {
	if (!b58_sha256_impl)
		b58_sha256_impl = blkmk_sha256_impl;
	return b58check(bin, binsz, base58str, 34);
}

static const int b58tobin_tbl[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57
};

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
    uint32_t c, bin32[7];
    uint64_t t;
    int len, i, j;

    // Validate output buffer size
    if (binsz < 25) {
        return false;
    }

    // Initialize intermediate binary storage
    memset(bin32, 0, sizeof(bin32));
    len = strlen(b58);

    // Decode Base58 string
    for (i = 0; i < len; i++) {
        c = b58[i];
        c = b58tobin_tbl[c]; // Use lookup table for decoding
        if (c == (uint32_t)-1) {
            return false; // Invalid character
        }
        for (j = 6; j >= 0; j--) {
            t = ((uint64_t)bin32[j]) * 58 + c;
            c = (t & 0x3f00000000ull) >> 32;
            bin32[j] = t & 0xffffffffull;
        }
    }

    // Convert decoded binary to output format
    *(bin++) = bin32[0] & 0xff;
    for (i = 1; i < 7; i++) {
        *((uint32_t *)bin) = htobe32(bin32[i]);
        bin += sizeof(uint32_t);
    }

    return true;
}


// size_t blkmk_address_to_scripts(void *out, size_t outsz, const char *addr) {
// 	unsigned char addrbin[25];
// 	unsigned char *cout = out;
// 	const size_t b58sz = strlen(addr);
// 	int addrver;
// 	size_t rv;
	
// 	rv = sizeof(addrbin);
// 	if (!b58_sha256_impl)
// 		b58_sha256_impl = blkmk_sha256_impl;
// 	if (!b58tobin(addrbin, &rv, addr, b58sz))
// 		return 0;
// 	addrver = b58check(addrbin, sizeof(addrbin), addr, b58sz);
// 	switch (addrver) {
// 		case   0:  // Bitcoin pubkey hash
// 		case 111:  // Testnet pubkey hash
// 			if (outsz < (rv = 25))
// 				return rv;
// 			cout[ 0] = 0x76;  // OP_DUP
// 			cout[ 1] = 0xa9;  // OP_HASH160
// 			cout[ 2] = 0x14;  // push 20 bytes
// 			memcpy(&cout[3], &addrbin[1], 20);
// 			cout[23] = 0x88;  // OP_EQUALVERIFY
// 			cout[24] = 0xac;  // OP_CHECKSIG
// 			return rv;
// 		case   5:  // Bitcoin script hash
// 		case 196:  // Testnet script hash
// 			if (outsz < (rv = 23))
// 				return rv;
// 			cout[ 0] = 0xa9;  // OP_HASH160
// 			cout[ 1] = 0x14;  // push 20 bytes
// 			memcpy(&cout[2], &addrbin[1], 20);
// 			cout[22] = 0x87;  // OP_EQUAL
// 			return rv;
// 		default:
// 			return 0;
// 	}
// }


size_t blkmk_address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
    unsigned char b58bin[25];

    // Ensure output buffer size is sufficient
    if (outsz < 25) {
        return 25; // Return the required size
    }

    // Initialize b58bin to zero
    memset(b58bin, 0, sizeof(b58bin));

    // Convert Base58 address to binary representation
    b58dec(b58bin, sizeof(b58bin), addr);

    // Construct the pubkey hash script
    out[0] = 0x76;                // OP_DUP
    out[1] = 0xa9;                // OP_HASH160
    out[2] = 0x14;                // Push 20 bytes
    memcpy(&out[3], &b58bin[1], 20); // Copy 20 bytes of the pubkey hash
    out[23] = 0x88;               // OP_EQUALVERIFY
    out[24] = 0xac;               // OP_CHECKSIG

    // Return the size of the generated script
    return 25;
}

