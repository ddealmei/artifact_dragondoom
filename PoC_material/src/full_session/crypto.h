/*
 * Wrapper functions for crypto libraries
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * This file defines the cryptographic functions that need to be implemented
 * for wpa_supplicant and hostapd. When TLS is not used, internal
 * implementation of MD5, SHA1, and AES is used and no external libraries are
 * required. When TLS is enabled (e.g., by enabling EAP-TLS or EAP-PEAP), the
 * crypto library used by the TLS implementation is expected to be used for
 * non-TLS needs, too, in order to save space by not implementing these
 * functions twice.
 *
 * Wrapper code for using each crypto library is in its own file (crypto*.c)
 * and one of these files is build and linked in to provide the functions
 * defined here.
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

// #define DEBUG 1

/**
 * crypto_get_random - Generate cryptographically strong pseudy-random bytes. Only used to generate a public parameter
 * @buf: Buffer for data  - PUBLIC
 * @len: Number of bytes to generate - PUBLIC
 * Returns: 0 on success, -1 on failure
 *
 * If the PRNG does not have enough entropy to ensure unpredictable byte
 * sequence, this functions must return -1.
 */
int crypto_get_random(void *buf, size_t len);


/**
 * struct crypto_bignum - bignum
 *
 * Internal data structure for bignum implementation. The contents is specific
 * to the used crypto library.
 */
struct crypto_bignum;

void crypto_bignum_print(char *label, const struct crypto_bignum* x);


/**
 * crypto_bignum_init - Allocate memory for bignum
 * Returns: Pointer to allocated bignum or %NULL on failure
 */
struct crypto_bignum * crypto_bignum_init(void);

/**
 * crypto_bignum_init_set - Allocate memory for bignum and set the value
 * @buf: Buffer with unsigned binary value  - usually SECRET, but may be public in some cases
 * @len: Length of buf in octets - usually PUBLIC
 * Returns: Pointer to allocated bignum or %NULL on failure - same as @buf
 */
struct crypto_bignum * crypto_bignum_init_set(const uint8_t *buf, size_t len);

/**
 * crypto_bignum_deinit - Free bignum
 * @n: Bignum from crypto_bignum_init() or crypto_bignum_init_set() - usually SECRET
 * @clear: Whether to clear the value from memory
 */
void crypto_bignum_deinit(struct crypto_bignum *n, int clear);

/**
 * crypto_bignum_to_bin - Set binary buffer to unsigned bignum
 * @a: Bignum   - usually SECRET, but may vary
 * @buf: Buffer for the binary number - SECRET <=> @a is secret
 * @len: Length of @buf in octets - PUBLIC
 * @padlen: Length in octets to pad the result to or 0 to indicate no padding   - PUBLIC
 * Returns: Number of octets written on success, -1 on failure
 */
int crypto_bignum_to_bin(const struct crypto_bignum *a,
			 uint8_t *buf, size_t buflen, size_t padlen);

/**
 * crypto_bignum_rand - Create a random number in range of modulus
 * @r: Bignum; set to a random value  - SECRET
 * @m: Bignum; modulus  - PUBLIC
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m);

/**
 * crypto_bignum_add - c = a + b
 * @a: Bignum   - usually SECRET, but may be PUBLIC
 * @b: Bignum   - usually SECRET, but may be PUBLIC
 * @c: Bignum; used to store the result of a + b    - usually SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_add(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c);

/**
 * crypto_bignum_mod - c = a % b
 * @a: Bignum - SECRET
 * @b: Bignum - PUBLIC
 * @c: Bignum; used to store the result of a % b    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_mod(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c);

/**
 * crypto_bignum_sub - c = a - b. Only used with public parameters for sae
 * @a: Bignum   - PUBLIC
 * @b: Bignum   - PUBLIC
 * @c: Bignum; used to store the result of a - b - PUBLIC
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_sub(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c);

/**
 * crypto_bignum_mulmod - d = a * b (mod c)
 * @a: Bignum   - SECRET
 * @b: Bignum   - SECRET
 * @c: Bignum   - PUBLIC
 * @d: Bignum; used to store the result of (a * b) % c  - PUBLIC (masked value in sae)
 * Returns: 0 on success, -1 on failure
 */
int crypto_bignum_mulmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 const struct crypto_bignum *c,
			 struct crypto_bignum *d);

/**
 * crypto_bignum_cmp - Compare two bignums.
 * @a: Bignum   - PUBLIC
 * @b: Bignum   - PUBLIC
 * Returns: -1 if a < b, 0 if a == b, or 1 if a > b
 */
int crypto_bignum_cmp(const struct crypto_bignum *a,
		      const struct crypto_bignum *b);

/**
 * crypto_bignum_is_zero - Is the given bignum zero
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is zero or 0 if not
 */
int crypto_bignum_is_zero(const struct crypto_bignum *a);

/**
 * crypto_bignum_is_one - Is the given bignum one
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is one or 0 if not
 */
int crypto_bignum_is_one(const struct crypto_bignum *a);

/**
 * crypto_bignum_is_odd - Is the given bignum odd
 * @a: Bignum   - SECRET
 * Returns: 1 if @a is odd or 0 if not
 */
int crypto_bignum_is_odd(const struct crypto_bignum *a);

/**
 * crypto_bignum_legendre - Compute the Legendre symbol (a/p)
 * @a: Bignum   - SECRET (mask here)
 * @p: Bignum   - PUBLIC
 * Returns: Legendre symbol -1,0,1 on success; -2 on calculation failure
 */
int crypto_bignum_legendre(const struct crypto_bignum *a,
			   const struct crypto_bignum *p);

/**
 * struct crypto_ec - Elliptic curve context
 *
 * Internal data structure for EC implementation. The contents is specific
 * to the used crypto library.
 */
struct crypto_ec;

/**
 * crypto_ec_init - Initialize elliptic curve context
 * @group: Identifying number for the ECC group (IANA "Group Description"
 *	attribute registrty for RFC 2409)   - PUBLIC
 * Returns: Pointer to EC context or %NULL on failure
 */
struct crypto_ec * crypto_ec_init(int group);

/**
 * crypto_ec_deinit - Deinitialize elliptic curve context
 * @e: EC context from crypto_ec_init() - PUBLIC
 */
void crypto_ec_deinit(struct crypto_ec *e);

/**
 * crypto_ec_prime_len - Get length of the prime in octets
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Length of the prime defining the group   - PUBLIC
 */
size_t crypto_ec_prime_len(struct crypto_ec *e);

/**
 * crypto_ec_prime_len_bits - Get length of the prime in bits
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Length of the prime defining the group in bits  - PUBLIC
 */
size_t crypto_ec_prime_len_bits(struct crypto_ec *e);

/**
 * crypto_ec_order_len - Get length of the order in octets
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Length of the order defining the group  - PUBLIC
 */
size_t crypto_ec_order_len(struct crypto_ec *e);

/**
 * crypto_ec_get_prime - Get prime defining an EC group
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Prime (bignum) defining the group   - PUBLIC
 */
const struct crypto_bignum * crypto_ec_get_prime(struct crypto_ec *e);

/**
 * crypto_ec_get_order - Get order of an EC group
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Order (bignum) of the group - PUBLIC
 */
const struct crypto_bignum * crypto_ec_get_order(struct crypto_ec *e);

/**
 * struct crypto_ec_point - Elliptic curve point
 *
 * Internal data structure for EC implementation to represent a point. The
 * contents is specific to the used crypto library.
 */
struct crypto_ec_point;

/**
 * crypto_ec_point_init - Initialize data for an EC point
 * @e: EC context from crypto_ec_init() - PUBLIC
 * Returns: Pointer to EC point data or %NULL on failure    - PUBLIC for now, may become SECRET later
 */
struct crypto_ec_point * crypto_ec_point_init(struct crypto_ec *e);

/**
 * crypto_ec_point_deinit - Deinitialize EC point data
 * @p: EC point data from crypto_ec_point_init()    - can be both PUBLIC or SECRET
 * @clear: Whether to clear the EC point value from memory
 */
void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear);


/**
 * crypto_ec_point_to_bin - Write EC point value as binary data
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point data from crypto_ec_point_init()       - can be both PUBLIC or SECRET
 * @x: Buffer for writing the binary data for x coordinate or %NULL if not used - same as @p
 * @y: Buffer for writing the binary data for y coordinate or %NULL if not used - same as @p
 * Returns: 0 on success, -1 on failure
 *
 * This function can be used to write an EC point as binary data in a format
 * that has the x and y coordinates in big endian byte order fields padded to
 * the length of the prime defining the group.
 */
int crypto_ec_point_to_bin(struct crypto_ec *e,
			   const struct crypto_ec_point *point, uint8_t *x, uint8_t *y);

/**
 * crypto_ec_point_from_bin - Create EC point from binary data
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @val: Binary data to read the EC point from  - can be both PUBLIC or SECRET
 * Returns: Pointer to EC point data or %NULL on failure    - same as @val
 *
 * This function readers x and y coordinates of the EC point from the provided
 * buffer assuming the values are in big endian byte order with fields padded to
 * the length of the prime defining the group.
 */
struct crypto_ec_point * crypto_ec_point_from_bin(struct crypto_ec *e,
						  const uint8_t *val);

/**
 * crypto_ec_point_add - c = a + b
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @a: Bignum   - SECRET
 * @b: Bignum   - PUBLIC
 * @c: Bignum; used to store the result of a + b    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_add(struct crypto_ec *e, const struct crypto_ec_point *a,
			const struct crypto_ec_point *b,
			struct crypto_ec_point *c);

/**
 * crypto_ec_point_mul - res = b * p
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point - SECRET
 * @b: Bignum   - SECRET
 * @res: EC point; used to store the result of b * p    - SECRET
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_mul(struct crypto_ec *e, const struct crypto_ec_point *p,
			const struct crypto_bignum *b,
			struct crypto_ec_point *res);

/**
 * crypto_ec_point_invert - Compute inverse of an EC point
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point to invert (and result of the operation) - PUBLIC
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p);

/**
 * crypto_ec_point_solve_y_coord - Solve y coordinate for an x coordinate
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point to use for the returning the result - SECRET
 * @x: x coordinate - SECRET
 * @y_bit: y-bit (0 or 1) for selecting the y value to use  - SECRET
 *
 * We found a vulnerability in OpenSSL in this call because @y_bit is not handled as a secret.
 *
 * Returns: 0 on success, -1 on failure
 */
int crypto_ec_point_solve_y_coord(struct crypto_ec *e,
				  struct crypto_ec_point *p,
				  const struct crypto_bignum *x, int y_bit);

/**
 * crypto_ec_point_compute_y_sqr - Compute y^2 = x^3 + ax + b
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @x: x coordinate - SECRET
 * Returns: y^2 on success, %NULL failure   - SECRET
 */
struct crypto_bignum *
crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
			      const struct crypto_bignum *x);

/**
 * crypto_ec_point_is_at_infinity - Check whether EC point is neutral element
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point - SECRET
 * Returns: 1 if the specified EC point is the neutral element of the group or
 *	0 if not
 */
int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
				   const struct crypto_ec_point *p);

/**
 * crypto_ec_point_is_on_curve - Check whether EC point is on curve
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @p: EC point - SECRET
 * Returns: 1 if the specified EC point is on the curve or 0 if not
 */
int crypto_ec_point_is_on_curve(struct crypto_ec *e,
				const struct crypto_ec_point *p);

/**
 * crypto_ec_point_cmp - Compare two EC points
 * @e: EC context from crypto_ec_init() - PUBLIC
 * @a: EC point - PUBLIC
 * @b: EC point - PUBLIC
 * Returns: 0 on equal, non-zero otherwise
 */
int crypto_ec_point_cmp(const struct crypto_ec *e,
			const struct crypto_ec_point *a,
			const struct crypto_ec_point *b);

#endif /* CRYPTO_H */
