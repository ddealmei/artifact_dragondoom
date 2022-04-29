/*
 * SHA256 hash implementation and interface functions
 * Copyright (c) 2003-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

#define SHA256_MAC_LEN 32

/**
 * HMAC-SHA256
 * @param key - SECRET
 * @param key_len  - SECRET
 * @param num_elem - PUBLIC
 * @param addr - PUBLIC
 * @param len - PUBLIC
 * @param mac - SECRET
 * @return
 */
int hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t *len, uint8_t *mac);
/**
 *
 * @param key - SECRET
 * @param key_len  - SECRET
 * @param data - PUBLIC
 * @param data_len  - PUBLIC
 * @param mac - SECRET
 * @return
 */
int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
		size_t data_len, uint8_t *mac);

/**
 * sha256_prf - SHA256-based Pseudo-Random Function (IEEE 802.11r, 8.5.1.5.2)
 * @key: Key for PRF    - SECRET
 * @key_len: Length of the key in bytes - PUBLIC
 * @label: A unique label for each purpose of the PRF   - PUBLIC
 * @data: Extra data to bind into the key   - PUBLIC;
 * @data_len: Length of the data    - SECRET
 * @buf: Buffer for the generated pseudo-random key - SECRET
 * @buf_len: Number of bytes of key to generate - PUBLIC
 * Returns: 0 on success, -1 on failure
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key.
 */
int sha256_prf(const uint8_t *key, size_t key_len, const char *label,
	       const uint8_t *data, size_t data_len, uint8_t *buf, size_t buf_len);

/**
 * sha256_prf_bits - IEEE Std 802.11-2012, 11.6.1.7.2 Key derivation function
 * @key: Key for PRF    - SECRET
 * @key_len: Length of the key in bytes - PUBLIC
 * @label: A unique label for each purpose of the PRF   - PUBLIC
 * @data: Extra data to bind into the key   - PUBLIC
 * @data_len: Length of the data    - SECRET
 * @buf: Buffer for the generated pseudo-random key - SECRET
 * @buf_len: Number of bytes of key to generate - PUBLIC
 * Returns: 0 on success, -1 on failure
 *
 * This function is used to derive new, cryptographically separate keys from a
 * given key. If the requested buf_len is not divisible by eight, the least
 * significant 1-7 bits of the last octet in the output are not part of the
 * requested output.
 */
int sha256_prf_bits(const uint8_t *key, size_t key_len, const char *label,
		    const uint8_t *data, size_t data_len, uint8_t *buf,
		    size_t buf_len_bits);

#endif /* SHA256_H */
