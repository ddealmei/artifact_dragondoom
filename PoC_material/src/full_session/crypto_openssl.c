/*
 * Wrapper functions for OpenSSL libcrypto
 * Copyright (c) 2004-2017, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */


#include <openssl/opensslv.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/ec.h>

#include <stdint.h>
#include <string.h>

#include "const_time.h"
#include "crypto.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L || \
	(defined(LIBRESSL_VERSION_NUMBER) && \
	 LIBRESSL_VERSION_NUMBER < 0x20700000L)
/* Compatibility wrappers for older versions. */

static HMAC_CTX * HMAC_CTX_new(void)
{
	HMAC_CTX *ctx;

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx)
		HMAC_CTX_init(ctx);
	return ctx;
}


static void HMAC_CTX_free(HMAC_CTX *ctx)
{
	if (!ctx)
		return;
	HMAC_CTX_cleanup(ctx);
	bin_clear_free(ctx, sizeof(*ctx));
}


static EVP_MD_CTX * EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *ctx;

	ctx = os_zalloc(sizeof(*ctx));
	if (ctx)
		EVP_MD_CTX_init(ctx);
	return ctx;
}


static void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
	if (!ctx)
		return;
	EVP_MD_CTX_cleanup(ctx);
	bin_clear_free(ctx, sizeof(*ctx));
}

#endif /* OpenSSL version < 1.1.0 */


static int openssl_hmac_vector(const EVP_MD *type, const uint8_t *key,
			       size_t key_len, size_t num_elem,
			       const uint8_t *addr[], const size_t *len, uint8_t *mac,
			       unsigned int mdlen)
{
	HMAC_CTX *ctx;
	size_t i;
	int res;

	
	ctx = HMAC_CTX_new();
	if (!ctx)
		return -1;
	res = HMAC_Init_ex(ctx, key, key_len, type, NULL);
	if (res != 1)
		goto done;

	for (i = 0; i < num_elem; i++)
		HMAC_Update(ctx, addr[i], len[i]);

	res = HMAC_Final(ctx, mac, &mdlen);
done:
	HMAC_CTX_free(ctx);

	return res == 1 ? 0 : -1;
}


int hmac_sha256_vector(const uint8_t *key, size_t key_len, size_t num_elem,
		       const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	return openssl_hmac_vector(EVP_sha256(), key, key_len, num_elem, addr,
				   len, mac, 32);
}


int hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data,
		size_t data_len, uint8_t *mac)
{
	return hmac_sha256_vector(key, key_len, 1, &data, &data_len, mac);
}


int crypto_get_random(void *buf, size_t len)
{
	if (RAND_bytes(buf, len) != 1)
		return -1;
	return 0;
}


void crypto_bignum_print(char *label, const struct crypto_bignum* x) {
#ifdef DEBUG
	char* number_str = BN_bn2hex((const BIGNUM*)x);
	fprintf(stderr, "%s: %s\n", label, number_str);
	OPENSSL_free(number_str);
#endif
}

struct crypto_bignum * crypto_bignum_init(void)
{
		return (struct crypto_bignum *) BN_new();
}


struct crypto_bignum * crypto_bignum_init_set(const uint8_t *buf, size_t len)
{
	BIGNUM *bn;
	
	bn = BN_bin2bn(buf, len, NULL);
	return (struct crypto_bignum *) bn;
}


void crypto_bignum_deinit(struct crypto_bignum *n, int clear)
{
	if (clear)
		BN_clear_free((BIGNUM *) n);
	else
		BN_free((BIGNUM *) n);
}


int crypto_bignum_to_bin(const struct crypto_bignum *a,
			 uint8_t *buf, size_t buflen, size_t padlen)
{
	int num_bytes, offset;

	
	if (padlen > buflen)
		return -1;

	if (padlen) {
#ifdef OPENSSL_IS_BORINGSSL
		if (BN_bn2bin_padded(buf, padlen, (const BIGNUM *) a) == 0)
			return -1;
		return padlen;
#else /* OPENSSL_IS_BORINGSSL */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L && !defined(LIBRESSL_VERSION_NUMBER)
		return BN_bn2binpad((const BIGNUM *) a, buf, padlen);
#endif
#endif
	}

	num_bytes = BN_num_bytes((const BIGNUM *) a);
	if ((size_t) num_bytes > buflen)
		return -1;
	if (padlen > (size_t) num_bytes)
		offset = padlen - num_bytes;
	else
		offset = 0;

	memset(buf, 0, offset);
	BN_bn2bin((const BIGNUM *) a, buf + offset);

	return num_bytes + offset;
}


int crypto_bignum_rand(struct crypto_bignum *r, const struct crypto_bignum *m)
{
		return BN_rand_range((BIGNUM *) r, (const BIGNUM *) m) == 1 ? 0 : -1;
}


int crypto_bignum_add(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c)
{
	return BN_add((BIGNUM *) c, (const BIGNUM *) a, (const BIGNUM *) b) ?
		0 : -1;
}


int crypto_bignum_mod(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c)
{
	int res;
	BN_CTX *bnctx;

	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -1;
	res = BN_mod((BIGNUM *) c, (const BIGNUM *) a, (const BIGNUM *) b,
		     bnctx);
	BN_CTX_free(bnctx);

	return res ? 0 : -1;
}


int crypto_bignum_sub(const struct crypto_bignum *a,
		      const struct crypto_bignum *b,
		      struct crypto_bignum *c)
{
		return BN_sub((BIGNUM *) c, (const BIGNUM *) a, (const BIGNUM *) b) ?
		0 : -1;
}

int crypto_bignum_mulmod(const struct crypto_bignum *a,
			 const struct crypto_bignum *b,
			 const struct crypto_bignum *c,
			 struct crypto_bignum *d)
{
	int res;

	BN_CTX *bnctx;

	
	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -1;
	res = BN_mod_mul((BIGNUM *) d, (const BIGNUM *) a, (const BIGNUM *) b,
			 (const BIGNUM *) c, bnctx);
	BN_CTX_free(bnctx);

	return res ? 0 : -1;
}


int crypto_bignum_cmp(const struct crypto_bignum *a,
		      const struct crypto_bignum *b)
{
	return BN_cmp((const BIGNUM *) a, (const BIGNUM *) b);
}


int crypto_bignum_is_zero(const struct crypto_bignum *a)
{
	return BN_is_zero((const BIGNUM *) a);
}


int crypto_bignum_is_one(const struct crypto_bignum *a)
{
	return BN_is_one((const BIGNUM *) a);
}


int crypto_bignum_is_odd(const struct crypto_bignum *a)
{
	return BN_is_odd((const BIGNUM *) a);
}


int crypto_bignum_legendre(const struct crypto_bignum *a,
			   const struct crypto_bignum *p)
{
	BN_CTX *bnctx;
	BIGNUM *exp = NULL, *tmp = NULL;
	int res = -2;
	unsigned int mask;

	
	bnctx = BN_CTX_new();
	if (bnctx == NULL)
		return -2;

	exp = BN_new();
	tmp = BN_new();
	if (!exp || !tmp ||
	    /* exp = (p-1) / 2 */
	    !BN_sub(exp, (const BIGNUM *) p, BN_value_one()) ||
	    !BN_rshift1(exp, exp) ||
	    !BN_mod_exp_mont_consttime(tmp, (const BIGNUM *) a, exp,
				       (const BIGNUM *) p, bnctx, NULL))
		goto fail;
	
	// fprintf(stderr, "legendre symbol:\n");
	// crypto_bignum_print("  a", a);
	// crypto_bignum_print("  t", (const struct crypto_bignum*) tmp);

	/* Return 1 if tmp == 1, 0 if tmp == 0, or -1 otherwise. Need to use
	 * constant time selection to avoid branches here. */
	res = -1;
	mask = const_time_eq(BN_is_word(tmp, 1), 1);
	res = const_time_select_int(mask, 1, res);
	mask = const_time_eq(BN_is_zero(tmp), 1);
	res = const_time_select_int(mask, 0, res);

fail:
	BN_clear_free(tmp);
	BN_clear_free(exp);
	BN_CTX_free(bnctx);
	return res;
}

/* EC as defined for OpenSSL, if we use HaCl*, we can simply redefine it */
struct crypto_ec {
	EC_GROUP *group;
	int nid;
	BN_CTX *bnctx;
	BIGNUM *prime;
	BIGNUM *order;
	BIGNUM *a;
	BIGNUM *b;
};

struct crypto_ec * crypto_ec_init(int group)
{
	struct crypto_ec *e;
	int nid;

	/* Map from IANA registry for IKE D-H groups to OpenSSL NID */
	switch (group) {
	case 19:
		nid = NID_X9_62_prime256v1;
		break;
	/* Only support P256 for now
	case 20:
		nid = NID_secp384r1;
		break;
	case 21:
		nid = NID_secp521r1;
		break;
	case 25:
		nid = NID_X9_62_prime192v1;
		break;
	case 26:
		nid = NID_secp224r1;
		break;
	case 27:
		nid = NID_brainpoolP224r1;
		break;
#ifdef NID_brainpoolP256r1
	case 28:
		nid = NID_brainpoolP256r1;
		break;
	case 29:
		nid = NID_brainpoolP384r1;
		break;
	case 30:
		nid = NID_brainpoolP512r1;
		break;
*/
	default:
		return NULL;
	}

	e = malloc(sizeof(*e));
	if (e == NULL)
		return NULL;
	memset(e, 0, sizeof(*e)),

	e->nid = nid;
	e->bnctx = BN_CTX_new();
	e->group = EC_GROUP_new_by_curve_name(nid);
	e->prime = BN_new();
	e->order = BN_new();
	e->a = BN_new();
	e->b = BN_new();
	if (e->group == NULL || e->bnctx == NULL || e->prime == NULL ||
	    e->order == NULL || e->a == NULL || e->b == NULL ||
	    !EC_GROUP_get_curve_GFp(e->group, e->prime, e->a, e->b, e->bnctx) ||
	    !EC_GROUP_get_order(e->group, e->order, e->bnctx)) {
		crypto_ec_deinit(e);
		e = NULL;
	}

	return e;
}


void crypto_ec_deinit(struct crypto_ec *e)
{
	if (e == NULL)
		return;
	BN_clear_free(e->b);
	BN_clear_free(e->a);
	BN_clear_free(e->order);
	BN_clear_free(e->prime);
	EC_GROUP_free(e->group);
	BN_CTX_free(e->bnctx);
	free(e);
}


struct crypto_ec_point * crypto_ec_point_init(struct crypto_ec *e)
{
    if (e == NULL)
		return NULL;
	return (struct crypto_ec_point *) EC_POINT_new(e->group);
}


size_t crypto_ec_prime_len(struct crypto_ec *e)
{
	return BN_num_bytes(e->prime);
}


size_t crypto_ec_prime_len_bits(struct crypto_ec *e)
{
	return BN_num_bits(e->prime);
}


size_t crypto_ec_order_len(struct crypto_ec *e)
{
	return BN_num_bytes(e->order);
}


const struct crypto_bignum * crypto_ec_get_prime(struct crypto_ec *e)
{
	return (const struct crypto_bignum *) e->prime;
}


const struct crypto_bignum * crypto_ec_get_order(struct crypto_ec *e)
{
	return (const struct crypto_bignum *) e->order;
}


void crypto_ec_point_deinit(struct crypto_ec_point *p, int clear)
{
	if (clear)
		EC_POINT_clear_free((EC_POINT *) p);
	else
		EC_POINT_free((EC_POINT *) p);
}

int crypto_ec_point_to_bin(struct crypto_ec *e,
			   const struct crypto_ec_point *point, uint8_t *x, uint8_t *y)
{
	BIGNUM *x_bn, *y_bn;
	int ret = -1;
	int len = BN_num_bytes(e->prime);

	x_bn = BN_new();
	y_bn = BN_new();

	if (x_bn && y_bn &&
	    EC_POINT_get_affine_coordinates_GFp(e->group, (EC_POINT *) point,
						x_bn, y_bn, e->bnctx)) {
		if (x) {
			crypto_bignum_to_bin((struct crypto_bignum *) x_bn,
					     x, len, len);
		}
		if (y) {
			crypto_bignum_to_bin((struct crypto_bignum *) y_bn,
					     y, len, len);
		}
		ret = 0;
	}

	BN_clear_free(x_bn);
	BN_clear_free(y_bn);
	return ret;
}


struct crypto_ec_point * crypto_ec_point_from_bin(struct crypto_ec *e,
						  const uint8_t *val)
{
	BIGNUM *x, *y;
	EC_POINT *elem;
	int len = BN_num_bytes(e->prime);

	
	x = BN_bin2bn(val, len, NULL);
	y = BN_bin2bn(val + len, len, NULL);
	elem = EC_POINT_new(e->group);
	if (x == NULL || y == NULL || elem == NULL) {
		BN_clear_free(x);
		BN_clear_free(y);
		EC_POINT_clear_free(elem);
		return NULL;
	}

	if (!EC_POINT_set_affine_coordinates_GFp(e->group, elem, x, y,
						 e->bnctx)) {
		EC_POINT_clear_free(elem);
		elem = NULL;
	}

	BN_clear_free(x);
	BN_clear_free(y);

	return (struct crypto_ec_point *) elem;
}


int crypto_ec_point_add(struct crypto_ec *e, const struct crypto_ec_point *a,
			const struct crypto_ec_point *b,
			struct crypto_ec_point *c)
{
		return EC_POINT_add(e->group, (EC_POINT *) c, (const EC_POINT *) a,
			    (const EC_POINT *) b, e->bnctx) ? 0 : -1;
}


int crypto_ec_point_mul(struct crypto_ec *e, const struct crypto_ec_point *p,
			const struct crypto_bignum *b,
			struct crypto_ec_point *res)
{
		return EC_POINT_mul(e->group, (EC_POINT *) res, NULL,
			    (const EC_POINT *) p, (const BIGNUM *) b, e->bnctx)
		? 0 : -1;
}


int crypto_ec_point_invert(struct crypto_ec *e, struct crypto_ec_point *p)
{
		return EC_POINT_invert(e->group, (EC_POINT *) p, e->bnctx) ? 0 : -1;
}


int crypto_ec_point_solve_y_coord(struct crypto_ec *e,
				  struct crypto_ec_point *p,
				  const struct crypto_bignum *x, int y_bit)
{
    
	// fprintf(stderr, "y coord computation:\n");
	// crypto_bignum_print("\tx_bn", x);
	// We found some cache attack in this function, because of a branching on the value of y_bit
    if (!EC_POINT_set_compressed_coordinates_GFp(e->group, (EC_POINT *) p, (const BIGNUM *) x, y_bit, e->bnctx) ||
        !EC_POINT_is_on_curve(e->group, (EC_POINT *) p, e->bnctx))
		return -1;
	return 0;
}


struct crypto_bignum *
crypto_ec_point_compute_y_sqr(struct crypto_ec *e,
			      const struct crypto_bignum *x)
{
	BIGNUM *tmp, *tmp2, *y_sqr = NULL;

	
	tmp = BN_new();
	tmp2 = BN_new();

	/* y^2 = x^3 + ax + b */
	if (tmp && tmp2 &&
	    BN_mod_sqr(tmp, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_mul(tmp, tmp, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_mul(tmp2, e->a, (const BIGNUM *) x, e->prime, e->bnctx) &&
	    BN_mod_add_quick(tmp2, tmp2, tmp, e->prime) &&
	    BN_mod_add_quick(tmp2, tmp2, e->b, e->prime)) {
		y_sqr = tmp2;
		tmp2 = NULL;
	}

	BN_clear_free(tmp);
	BN_clear_free(tmp2);

	return (struct crypto_bignum *) y_sqr;
}


int crypto_ec_point_is_at_infinity(struct crypto_ec *e,
				   const struct crypto_ec_point *p)
{
	return EC_POINT_is_at_infinity(e->group, (const EC_POINT *) p);
}


int crypto_ec_point_is_on_curve(struct crypto_ec *e,
				const struct crypto_ec_point *p)
{
	return EC_POINT_is_on_curve(e->group, (const EC_POINT *) p,
				    e->bnctx) == 1;
}


int crypto_ec_point_cmp(const struct crypto_ec *e,
			const struct crypto_ec_point *a,
			const struct crypto_ec_point *b)
{
	return EC_POINT_cmp(e->group, (const EC_POINT *) a,
			    (const EC_POINT *) b, e->bnctx);
}
