/*
 * SHA256-based PRF (IEEE 802.11r)
 * Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include <string.h>

#include "utils.h"
#include "sha256.h"

int sha256_prf(const uint8_t *key, size_t key_len, const char *label,
		const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len)
{
	return sha256_prf_bits(key, key_len, label, data, data_len, buf,
			       buf_len * 8);
}


int sha256_prf_bits(const uint8_t *key, size_t key_len, const char *label,
		    const uint8_t *data, size_t data_len, uint8_t *buf,
		    size_t buf_len_bits)
{
	uint16_t counter = 1;
	size_t pos, plen;
	uint8_t hash[SHA256_MAC_LEN];
	const uint8_t *addr[4];
	size_t len[4];
	uint8_t counter_le[2], length_le[2];
	size_t buf_len = (buf_len_bits + 7) / 8;

	addr[0] = counter_le;
	len[0] = 2;
	addr[1] = (uint8_t *) label;
	len[1] = strlen(label);
	addr[2] = data;
	len[2] = data_len;
	addr[3] = length_le;
	len[3] = sizeof(length_le);

	WPA_PUT_LE16(length_le, buf_len_bits);
	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		WPA_PUT_LE16(counter_le, counter);
		if (plen >= SHA256_MAC_LEN) {
			if (hmac_sha256_vector(key, key_len, 4, addr, len,
					       &buf[pos]) < 0)
				return -1;
			pos += SHA256_MAC_LEN;
		} else {
			if (hmac_sha256_vector(key, key_len, 4, addr, len,
					       hash) < 0)
				return -1;
			memcpy(&buf[pos], hash, plen);
			pos += plen;
			break;
		}
		counter++;
	}

	/*
	 * Mask out unused bits in the last octet if it does not use all the
	 * bits.
	 */
	if (buf_len_bits % 8) {
		uint8_t mask = 0xff << (8 - buf_len_bits % 8);
		buf[pos - 1] &= mask;
	}

	memset(hash, 0, sizeof(hash));

	return 0;
}
