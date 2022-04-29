/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <utils.h>

#include "const_time.h"
#include "crypto.h"
#include "sha256.h"
#include "sae.h"
#include "utils.h"
#include "wpabuf.h"


#define DRAGONFLY_MAX_ECC_PRIME_LEN 66
/* IEEE 802.22 codes defined in hostapd */
#define WLAN_STATUS_SUCCESS 0
#define WLAN_STATUS_UNSPECIFIED_FAILURE 1
#define WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED 77
#define WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER 123
#define WLAN_EID_EXTENSION 255
#define WLAN_EID_EXT_PASSWORD_IDENTIFIER 33


/**
 * Right shift the value in buf
 * @param buf - SECRET
 * @param len - PUBLIC
 * @param bits - SECRET
 */
void buf_shift_right(uint8_t *buf, size_t len, size_t bits)
{
	size_t i;

	for (i = len - 1; i > 0; i--)
		buf[i] = (buf[i - 1] << (8 - bits)) | (buf[i] >> bits);
	buf[0] >>= bits;
}

int dragonfly_suitable_group(int group, int ecc_only)
{
    /* Enforce REVmd rules on which SAE groups are suitable for production
     * purposes: FFC groups whose prime is >= 3072 bits and ECC groups
     * defined over a prime field whose prime is >= 256 bits. Furthermore,
     * ECC groups defined over a characteristic 2 finite field and ECC
     * groups with a co-factor greater than 1 are not suitable. Disable
     * groups that use Brainpool curves as well for now since they leak more
     * timing information due to the prime not being close to a power of
     * two. */
    return group == 19;
    // Only support P256 for a start, but P384 and P521 should also be supported (|| group == 20 || group == 21;)
    /* Additional check for ffc groups
     * || (!ecc_only &&
            (group == 15 || group == 16 || group == 17 || group == 18));
    */
}


unsigned int dragonfly_min_pwe_loop_iter(int group)
{
    /*
    if (group == 22 || group == 23 || group == 24) {
        // FFC groups for which pwd-value is likely to be >= p frequently
        return 40;
    }

    if (group == 1 || group == 2 || group == 5 || group == 14 ||
        group == 15 || group == 16 || group == 17 || group == 18) {
        // FFC groups that have prime that is close to a power of two
        return 1;
    }
    */

    /* Default to 40 (this covers most ECC groups) */
    return 40;
}


int dragonfly_get_random_qr_qnr(const struct crypto_bignum *prime,
                                struct crypto_bignum **qr,
                                struct crypto_bignum **qnr)
{
	*qr = *qnr = NULL;
	/* ddealmei: Instead of generating random qr / nqr, we generate them once
	 * and for all, and hardcode them. Tfis is only to remove randomness in our
	 * analysis. Original code can be found commented bellow. */
	unsigned char qr_bin[] = { 0xe4, 0xf3, 0x30, 0x16, 0xe5, 0x3d, 0x3b, 0xec, 0x8d, 0x71, 0x69, 0x90, 0x47, 0xf1, 0x0f, 0x89, 0xa0, 0x37, 0x77, 0x1e, 0x5a, 0x66, 0x31, 0x3e, 0xf9, 0x43, 0x9f, 0x64, 0x42, 0x4a, 0x8b, 0xaf };
	unsigned char qnr_bin[] = { 0xb9, 0x81, 0x2f, 0x01, 0x90, 0x10, 0x05, 0x9c, 0x98, 0x02, 0xc0, 0x57, 0x1a, 0xdf, 0xb3, 0x21, 0xbe, 0x97, 0x29, 0xa3, 0x4e, 0xd1, 0xd7, 0xf7, 0xe3, 0xd4, 0xe8, 0xd4, 0x57, 0xf8, 0x9b, 0xb4 };


	*qr = crypto_bignum_init_set(qr_bin, 32);
	*qnr = crypto_bignum_init_set(qnr_bin, 32);
	
	// while (!(*qr) || !(*qnr)) {
	// 	struct crypto_bignum *tmp;
	// 	int res;

	// 	tmp = crypto_bignum_init();
	// 	if (!tmp || crypto_bignum_rand(tmp, prime) < 0) {
	// 		crypto_bignum_deinit(tmp, 0);
	// 		break;
	// 	}

	// 	res = crypto_bignum_legendre(tmp, prime);
	// 	if (res == 1 && !(*qr))
	// 		*qr = tmp;
	// 	else if (res == -1 && !(*qnr))
	// 		*qnr = tmp;
	// 	else
	// 		crypto_bignum_deinit(tmp, 0);
	// }
	
	if (*qr && *qnr)
		return 0;
	crypto_bignum_deinit(*qr, 0);
	crypto_bignum_deinit(*qnr, 0);
	*qr = *qnr = NULL;
	return -1;
}


static struct crypto_bignum*
dragonfly_get_rand_1_to_p_1(const struct crypto_bignum* prime) {
	struct crypto_bignum* tmp, * pm1, * one;

	tmp = crypto_bignum_init();
	pm1 = crypto_bignum_init();
	one = crypto_bignum_init_set((const uint8_t*) "\x01", 1);
	if (!tmp || !pm1 || !one ||
		crypto_bignum_sub(prime, one, pm1) < 0 ||
		crypto_bignum_rand(tmp, pm1) < 0 ||
		crypto_bignum_add(tmp, one, tmp) < 0) {
		crypto_bignum_deinit(tmp, 0);
		tmp = NULL;
	}

	crypto_bignum_deinit(pm1, 0);
	crypto_bignum_deinit(one, 0);
	return tmp;
}


int dragonfly_is_quadratic_residue_blind(struct crypto_ec *ec,
                                         const uint8_t *qr, const uint8_t *qnr,
                                         const struct crypto_bignum *val)
{
    struct crypto_bignum *r, *num, *qr_or_qnr = NULL;
    int check, res = -1;
    uint8_t qr_or_qnr_bin[DRAGONFLY_MAX_ECC_PRIME_LEN];
    const struct crypto_bignum *prime;
    size_t prime_len;
    unsigned int mask;

    prime = crypto_ec_get_prime(ec);
    prime_len = crypto_ec_prime_len(ec);
	// crypto_bignum_print("y_sqr", val);
    /*
     * Use a blinding technique to mask val while determining whether it is
     * a quadratic residue modulo p to avoid leaking timing information
     * while determining the Legendre symbol.
     *
     * v = val
     * r = a random number between 1 and p-1, inclusive
     * num = (v * r * r) modulo p
     */
    r = dragonfly_get_rand_1_to_p_1(prime);
    if (!r)
        return -1;
	// crypto_bignum_print("mask", r);

    num = crypto_bignum_init();
    if (!num ||
        crypto_bignum_mulmod(val, r, prime, num) < 0 ||
        crypto_bignum_mulmod(num, r, prime, num) < 0)
        goto fail;
	// crypto_bignum_print("masked_value", num);
    /*
     * Need to minimize differences in handling different cases, so try to
     * avoid branches and timing differences.
     *
     * If r is odd:
     * num = (num * qr) module p
     * LGR(num, p) = 1 ==> quadratic residue
     * else:
     * num = (num * qnr) module p
     * LGR(num, p) = -1 ==> quadratic residue
     *
     * mask is set to !odd(r)
     */
    mask = const_time_is_zero(crypto_bignum_is_odd(r));
    const_time_select_bin(mask, qnr, qr, prime_len, qr_or_qnr_bin);
    qr_or_qnr = crypto_bignum_init_set(qr_or_qnr_bin, prime_len);
	// hexdump("qr bin: ", qr, prime_len);
	// hexdump("qnr bin: ", qnr, prime_len);
	// hexdump("qr_or_qnr bin: ", qr_or_qnr_bin, prime_len);
	// crypto_bignum_print("qr_or_qnr", qr_or_qnr);
    if (!qr_or_qnr ||
        crypto_bignum_mulmod(num, qr_or_qnr, prime, num) < 0)
        goto fail;
	// crypto_bignum_print("after qr masking", num);
    /* branchless version of check = odd(r) ? 1 : -1, */
    check = const_time_select_int(mask, -1, 1);

    /* Determine the Legendre symbol on the masked value */
    res = crypto_bignum_legendre(num, prime);
    if (res == -2) {
        res = -1;
        goto fail;
    }
    /* branchless version of res = res == check
     * (res is -1, 0, or 1; check is -1 or 1) */
    mask = const_time_eq(res, check);
    res = const_time_select_int(mask, 1, 0);
    fail:
    crypto_bignum_deinit(num, 1);
    crypto_bignum_deinit(r, 1);
    crypto_bignum_deinit(qr_or_qnr, 1);
    return res;
}


static int dragonfly_get_rand_2_to_r_1(struct crypto_bignum *val,
                                       const struct crypto_bignum *order)
{
    return crypto_bignum_rand(val, order) == 0 &&
           !crypto_bignum_is_zero(val) &&
           !crypto_bignum_is_one(val);
}


int dragonfly_generate_scalar(const struct crypto_bignum *order,
                              struct crypto_bignum *_rand,
                              struct crypto_bignum *_mask,
                              struct crypto_bignum *scalar)
{
    int count;

    /* Select two random values rand,mask such that 1 < rand,mask < r and
     * rand + mask mod r > 1. */
    for (count = 0; count < 100; count++) {
        if (dragonfly_get_rand_2_to_r_1(_rand, order) &&
            dragonfly_get_rand_2_to_r_1(_mask, order) &&
            crypto_bignum_add(_rand, _mask, scalar) == 0 &&
            crypto_bignum_mod(scalar, order, scalar) == 0 &&
            !crypto_bignum_is_zero(scalar) &&
            !crypto_bignum_is_one(scalar))
            return 0;
    }

    /* This should not be reachable in practice if the random number
     * generation is working. */
    fprintf(stderr,
            "dragonfly: Unable to get randomness for own scalar\n");
    return -1;
}

/**
 * Initialize the structure with the right group. For now we simply support P-256
 * @param sae   - PUBLIC
 * @param group - PUBLIC
 * @return 0 on success, -1 on failure
 */
int sae_set_group(struct sae_data *sae, int group)
{
	struct sae_temporary_data *tmp;

	if (!dragonfly_suitable_group(group, 0)) {
		return -1;
	}

	sae_clear_data(sae);
	tmp = sae->tmp = malloc(sizeof(*tmp));
	if (tmp == NULL)
		return -1;
	memset(tmp, 0, sizeof(*tmp));

	/* First, check if this is an ECC group, for now we only aim at supporting ecc */
	tmp->ec = crypto_ec_init(group);
	if (tmp->ec) {
		sae->group = group;
		tmp->prime_len = crypto_ec_prime_len(tmp->ec);
		tmp->prime = crypto_ec_get_prime(tmp->ec);
		tmp->order_len = crypto_ec_order_len(tmp->ec);
		tmp->order = crypto_ec_get_order(tmp->ec);
		return 0;
	}

	/* We skip support for FFC for now */
	return -1;
}

void sae_clear_temp_data(struct sae_data *sae)
{
	struct sae_temporary_data *tmp;
	if (sae == NULL || sae->tmp == NULL)
		return;
	tmp = sae->tmp;
	crypto_ec_deinit(tmp->ec);
	crypto_bignum_deinit(tmp->prime_buf, 0);
	crypto_bignum_deinit(tmp->order_buf, 0);
	crypto_bignum_deinit(tmp->sae_rand, 1);
	// crypto_bignum_deinit(tmp->pwe_ffc, 1);
	crypto_bignum_deinit(tmp->own_commit_scalar, 0);
	// crypto_bignum_deinit(tmp->own_commit_element_ffc, 0);
	// crypto_bignum_deinit(tmp->peer_commit_element_ffc, 0);
	crypto_ec_point_deinit(tmp->pwe_ecc, 1);
	crypto_ec_point_deinit(tmp->own_commit_element_ecc, 0);
	crypto_ec_point_deinit(tmp->peer_commit_element_ecc, 0);
	if (tmp->anti_clogging_token != NULL) free(tmp->anti_clogging_token);
	free(tmp->pw_id);
	memset(tmp, 0, sizeof(*tmp));
	free(tmp);
	sae->tmp = NULL;
}

void sae_clear_data(struct sae_data *sae)
{
	if (sae == NULL)
		return;
	sae_clear_temp_data(sae);
	crypto_bignum_deinit(sae->peer_commit_scalar, 0);
	memset(sae, 0, sizeof(*sae));
}

/**
 * Initialize the key base with the MAC addresses.
 * @param addr1 - PUBLIC
 * @param addr2 - PUBLIC
 * @param key   - PUBLIC (for now, but will be SECRET after)
 */
static void sae_pwd_seed_key(const uint8_t *addr1, const uint8_t *addr2, uint8_t *key)
{
	if (memcmp(addr1, addr2, ETH_ALEN) > 0) {
		memcpy(key, addr1, ETH_ALEN);
		memcpy(key + ETH_ALEN, addr2, ETH_ALEN);
	} else {
		memcpy(key, addr2, ETH_ALEN);
		memcpy(key + ETH_ALEN, addr1, ETH_ALEN);
	}
}

/**
 * Process the seed and see if it gives a valid point coordinates. Lots of sensitive operations inside
 * @param sae       - contains SECRET information
 * @param pwd_seed  - SECRET
 * @param prime     - PUBLIC
 * @param qr quadratic residue to be used in the mask is_square - SECRET (ephemeral value)
 * @param qnr quadratic non residue to be used in the mask is_square - SECRET (ephemeral value)
 * @param pwd_value - SECRET
 * @return
 */
static int sae_test_pwd_seed_ecc(struct sae_data *sae, const uint8_t *pwd_seed,
				 const uint8_t *prime, const uint8_t *qr, const uint8_t *qnr,
				 uint8_t *pwd_value)
{
	struct crypto_bignum *y_sqr, *x_cand;
	int res;
	size_t bits;
	int cmp_prime;
	unsigned int in_range;

	hexdump("SAE: pwd-seed", pwd_seed, SHA256_MAC_LEN);

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = crypto_ec_prime_len_bits(sae->tmp->ec);
	if (sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			    prime, sae->tmp->prime_len, pwd_value, bits) < 0)
		return -1;
	/* shift the buffer to be the appropriate bit-length if needed */
	if (bits % 8)
		buf_shift_right(pwd_value, sae->tmp->prime_len, 8 - bits % 8);

	hexdump("SAE: pwd-value", pwd_value, sae->tmp->prime_len);

	cmp_prime = const_time_memcmp(pwd_value, prime, (size_t) sae->tmp->prime_len);
	/* Create a const_time mask for selection based on prf result
	 * being smaller than prime. */
	in_range = const_time_fill_msb((unsigned int) cmp_prime);
	/* The algorithm description would skip the next steps if
	 * cmp_prime >= 0 (return 0 here), but go through them regardless to
	 * minimize externally observable differences in behavior. */

	x_cand = crypto_bignum_init_set(pwd_value, sae->tmp->prime_len);
	if (!x_cand)
		return -1;
	y_sqr = crypto_ec_point_compute_y_sqr(sae->tmp->ec, x_cand);
	crypto_bignum_deinit(x_cand, 1);
	if (!y_sqr)
		return -1;

	res = dragonfly_is_quadratic_residue_blind(sae->tmp->ec, qr, qnr,
						   y_sqr);
	crypto_bignum_deinit(y_sqr, 1);
	if (res < 0)
		return res;
	return const_time_select_int(in_range, res, 0);
}

/**
 * Main hash-to-curve function, converting the identity and the password to a point on the given curve
 * @param sae   - contains SECRET information
 * @param addr1 - PUBLIC
 * @param addr2 - PUBLIC
 * @param password - SECRET
 * @param password_len - SECRET
 * @param identifier - PUBLIC (can be NULL)
 * @return
 */
static int sae_derive_pwe_ecc(struct sae_data *sae, const uint8_t *addr1,
			      const uint8_t *addr2, const uint8_t *password,
			      size_t password_len, const char *identifier)
{
	uint8_t counter, k;
	uint8_t addrs[2 * ETH_ALEN];
	const uint8_t *addr[3];
	size_t len[3];
	size_t num_elem;
	uint8_t *dummy_password, *tmp_password;
	int pwd_seed_odd = 0;
	uint8_t prime[SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	struct crypto_bignum *x = NULL, *qr = NULL, *qnr = NULL;
	uint8_t x_bin[SAE_MAX_ECC_PRIME_LEN];
	uint8_t x_cand_bin[SAE_MAX_ECC_PRIME_LEN];
	uint8_t qr_bin[SAE_MAX_ECC_PRIME_LEN];
	uint8_t qnr_bin[SAE_MAX_ECC_PRIME_LEN];
	int res = -1;
	uint8_t found = 0; /* 0 (false) or 0xff (true) to be used as const_time_*
		       * mask */

	memset(x_bin, 0, sizeof(x_bin));

	dummy_password = malloc(password_len);
	tmp_password = malloc(password_len);
	/* ddealmei: Fix the dummy password to password so that we can compare resulst form reference and new implementation */
	if (!dummy_password || !tmp_password ||
		/*crypto_get_random(dummy_password, password_len) < 0*/memcpy(dummy_password, password, password_len) == NULL)
		goto fail;

	prime_len = sae->tmp->prime_len;
	if (crypto_bignum_to_bin(sae->tmp->prime, prime, sizeof(prime),
				 prime_len) < 0)
		goto fail;

	/*
	 * Create a random quadratic residue (qr) and quadratic non-residue
	 * (qnr) modulo p for blinding purposes during the loop.
	 */
	if (dragonfly_get_random_qr_qnr(sae->tmp->prime, &qr, &qnr) < 0 ||
	    crypto_bignum_to_bin(qr, qr_bin, sizeof(qr_bin), prime_len) < 0 ||
	    crypto_bignum_to_bin(qnr, qnr_bin, sizeof(qnr_bin), prime_len) < 0)
		goto fail;

	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * base = password [|| identifier]
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              base || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = tmp_password;
	len[0] = password_len;
	num_elem = 1;
	if (identifier) {
		addr[num_elem] = (const uint8_t *) identifier;
		len[num_elem] = strlen(identifier);
		num_elem++;
	}
	addr[num_elem] = &counter;
	len[num_elem] = sizeof(counter);
	num_elem++;

	/*
	 * Continue for at least k iterations to protect against side-channel
	 * attacks that attempt to determine the number of iterations required
	 * in the loop.
	 */
	k = dragonfly_min_pwe_loop_iter(sae->group);
	crypto_bignum_print("prime", sae->tmp->prime);
	hexdump("prime bin: ", prime, 32);
	for (counter = 1; counter <= k || !found; counter++) {
		uint8_t pwd_seed[SHA256_MAC_LEN];

		if (counter > 200) {
			fprintf(stderr, "SAE: Failed to derive PWE\n");
			/* This should not happen in practice */
			break;
		}

		const_time_select_bin(found, dummy_password, password,
				      password_len, tmp_password);
		if (hmac_sha256_vector(addrs, sizeof(addrs), num_elem,
				       addr, len, pwd_seed) < 0)
			break;

		res = sae_test_pwd_seed_ecc(sae, pwd_seed,
					    prime, qr_bin, qnr_bin, x_cand_bin);
		const_time_select_bin(found, x_bin, x_cand_bin, prime_len,
				      x_bin);
		pwd_seed_odd = const_time_select_u8(
			found, pwd_seed_odd,
			pwd_seed[SHA256_MAC_LEN - 1] & 0x01);
		memset(pwd_seed, 0, sizeof(pwd_seed));
		if (res < 0)
			goto fail;
		/* Need to minimize differences in handling res == 0 and 1 here
		 * to avoid differences in timing and instruction cache access,
		 * so use const_time_select_*() to make local copies of the
		 * values based on whether this loop iteration was the one that
		 * found the pwd-seed/x. */

		/* found is 0 or 0xff here and res is 0 or 1. Bitwise OR of them
		 * (with res converted to 0/0xff) handles this in constant time.
		 */
		found |= res * 0xff;
		#ifdef DEBUG
		fprintf(stderr, "SAE: pwd-seed result %d found=0x%02x\n", res, found);
		#endif
		}

	if (!found) {
		fprintf(stderr, "SAE: Could not generate PWE\n");
		res = -1;
		goto fail;
	}

	x = crypto_bignum_init_set(x_bin, prime_len);
	hexdump("x bin: ", x_bin, 32);
	// crypto_bignum_print("x_big", x);
	if (!x) {
		res = -1;
		goto fail;
	}

	if (!sae->tmp->pwe_ecc)
		sae->tmp->pwe_ecc = crypto_ec_point_init(sae->tmp->ec);
	if (!sae->tmp->pwe_ecc)
		res = -1;
	else
		res = crypto_ec_point_solve_y_coord(sae->tmp->ec,
						    sae->tmp->pwe_ecc, x,
						    pwd_seed_odd);
	if (res < 0) {
		fprintf(stderr, "SAE: Could not solve y\n");
		/*
		 * This should not happen since we already checked that there
		 * is a result.
		 */
	}

	// DEBUG information here, needed to get the ground truth
	// for (size_t i = 0; i < 32; i++)
	// {
	// 	printf("%02x", x_bin[i]);
	// }
	printf("%d %d\n", get_y_parity(x_bin, COORD_LEN, NID_P256), pwd_seed_odd);
	

fail:
	crypto_bignum_deinit(qr, 0);
	crypto_bignum_deinit(qnr, 0);
	free(dummy_password);
	memset(tmp_password, 0, password_len);
	free(tmp_password);
	crypto_bignum_deinit(x, 1);
	memset(x_bin, 0, sizeof(x_bin));
	memset(x_cand_bin, 0, sizeof(x_cand_bin));

	return res;
}


static int sae_derive_commit_element_ecc(struct sae_data *sae,
					 struct crypto_bignum *mask)
{
	/* COMMIT-ELEMENT = inverse(scalar-op(mask, PWE)) */
	if (!sae->tmp->own_commit_element_ecc) {
		sae->tmp->own_commit_element_ecc =
			crypto_ec_point_init(sae->tmp->ec);
		if (!sae->tmp->own_commit_element_ecc)
			return -1;
	}

	if (crypto_ec_point_mul(sae->tmp->ec, sae->tmp->pwe_ecc, mask,
				sae->tmp->own_commit_element_ecc) < 0 ||
	    crypto_ec_point_invert(sae->tmp->ec,
				   sae->tmp->own_commit_element_ecc) < 0) {
		fprintf(stderr, "SAE: Could not compute commit-element\n");
		return -1;
	}

	return 0;
}


static int sae_derive_commit(struct sae_data* sae) {
	struct crypto_bignum* mask;
	int ret;
	/* ddealmei: Here we set a constant mask to avoid its CF effects on the
		 * secret point coordinates. The mask has been generated randomly in
		 * python, and hardcoded. Original code is commented bellow. The idea is
		 * basically that we generate mask and sae_rand, and compute
		 * own_commit_scalar = mask + sae_rand mod p */
	uint8_t mask_bin[] = { 0x2b, 0x38, 0x7a, 0x22, 0xa5, 0xb3, 0x61, 0xf8, 0x0b, 0x0f, 0xc7, 0x27, 0x1e, 0x7f, 0xb4, 0x5e, 0xaa, 0x5d, 0x43, 0xa5, 0x55, 0x7a, 0xf8, 0x41, 0xd2, 0xcc, 0x65, 0x70, 0xd1, 0x4f, 0xfb, 0xdf };
	uint8_t sae_rand_bin[] = { 0x66, 0x11, 0xe9, 0xbc, 0x4c, 0x37, 0xd1, 0xc3, 0xd9, 0x7d, 0xe7, 0xad, 0x6b, 0x3e, 0x69, 0xcb, 0x00, 0x5f, 0xe9, 0xcb, 0xa0, 0x74, 0x52, 0xd0, 0xba, 0x16, 0x8a, 0xce, 0x53, 0xb0, 0x87, 0x56 };

	mask = crypto_bignum_init_set(mask_bin, 32);
	if (!sae->tmp->sae_rand)
		sae->tmp->sae_rand = crypto_bignum_init_set(sae_rand_bin, 32);
	if (!sae->tmp->own_commit_scalar)
		sae->tmp->own_commit_scalar = crypto_bignum_init();

	ret = !mask || !sae->tmp->sae_rand || !sae->tmp->own_commit_scalar ||
		crypto_bignum_add(sae->tmp->sae_rand, mask, sae->tmp->own_commit_scalar) != 0 ||
		crypto_bignum_mod(sae->tmp->own_commit_scalar, sae->tmp->order, sae->tmp->own_commit_scalar) != 0 ||
		(sae->tmp->ec && sae_derive_commit_element_ecc(sae, mask) < 0) /*||
		(sae->tmp->dh && sae_derive_commit_element_ffc(sae, mask) < 0)*/;
		/*
		mask = crypto_bignum_init();
		if (!sae->tmp->sae_rand)
			sae->tmp->sae_rand = crypto_bignum_init();
		if (!sae->tmp->own_commit_scalar)
			sae->tmp->own_commit_scalar = crypto_bignum_init();
		ret = !mask || !sae->tmp->sae_rand || !sae->tmp->own_commit_scalar ||
			dragonfly_generate_scalar(sae->tmp->order, sae->tmp->sae_rand,
						  mask,
						  sae->tmp->own_commit_scalar) < 0 ||
			(sae->tmp->ec &&
			 sae_derive_commit_element_ecc(sae, mask) < 0) ||
			(sae->tmp->dh &&
			 sae_derive_commit_element_ffc(sae, mask) < 0);
		*/
	crypto_bignum_deinit(mask, 1);
	return ret ? -1 : 0;
}


int sae_prepare_commit(const uint8_t *addr1, const uint8_t *addr2,
		       const uint8_t *password, size_t password_len,
		       const char *identifier, struct sae_data *sae)
{
	if (sae->tmp == NULL ||
	    (sae->tmp->ec && sae_derive_pwe_ecc(sae, addr1, addr2, password,
						password_len,
						identifier) < 0) ||
	    /* (sae->tmp->dh && sae_derive_pwe_ffc(sae, addr1, addr2, password,
						password_len,
						identifier) < 0) || */
	    sae_derive_commit(sae) < 0)
		return -1;
	return 0;
}


static int sae_derive_k_ecc(struct sae_data *sae, uint8_t *k)
{
	struct crypto_ec_point *K;
	int ret = -1;

	K = crypto_ec_point_init(sae->tmp->ec);
	if (K == NULL)
		goto fail;

	/*
	 * K = scalar-op(rand, (elem-op(scalar-op(peer-commit-scalar, PWE),
	 *                                        PEER-COMMIT-ELEMENT)))
	 * If K is identity element (point-at-infinity), reject
	 * k = F(K) (= x coordinate)
	 */

	if (crypto_ec_point_mul(sae->tmp->ec, sae->tmp->pwe_ecc,
				sae->peer_commit_scalar, K) < 0 ||
	    crypto_ec_point_add(sae->tmp->ec, K,
				sae->tmp->peer_commit_element_ecc, K) < 0 ||
	    crypto_ec_point_mul(sae->tmp->ec, K, sae->tmp->sae_rand, K) < 0 ||
	    crypto_ec_point_is_at_infinity(sae->tmp->ec, K) ||
	    crypto_ec_point_to_bin(sae->tmp->ec, K, k, NULL) < 0) {
		fprintf(stderr, "SAE: Failed to calculate K and k\n");
		goto fail;
	}
	hexdump("SAE: k", k, sae->tmp->prime_len);
	ret = 0;
fail:
	crypto_ec_point_deinit(K, 1);
	return ret;
}


static int sae_derive_keys(struct sae_data *sae, const uint8_t *k)
{
	uint8_t null_key[SAE_KEYSEED_KEY_LEN], val[SAE_MAX_PRIME_LEN];
	uint8_t keyseed[SHA256_MAC_LEN];
	uint8_t keys[SAE_KCK_LEN + SAE_PMK_LEN];
	struct crypto_bignum *tmp;
	int ret = -1;

	tmp = crypto_bignum_init();
	if (tmp == NULL)
		goto fail;

	/* keyseed = H(<0>32, k)
	 * KCK || PMK = KDF-512(keyseed, "SAE KCK and PMK",
	 *                      (commit-scalar + peer-commit-scalar) modulo r)
	 * PMKID = L((commit-scalar + peer-commit-scalar) modulo r, 0, 128)
	 */

	memset(null_key, 0, sizeof(null_key));
	hmac_sha256(null_key, sizeof(null_key), k, sae->tmp->prime_len,
		    keyseed);
	hexdump("SAE: keyseed", keyseed, sizeof(keyseed));
	crypto_bignum_add(sae->tmp->own_commit_scalar, sae->peer_commit_scalar,
			  tmp);
	crypto_bignum_mod(tmp, sae->tmp->order, tmp);

	crypto_bignum_print("order", sae->tmp->order);
	crypto_bignum_print("scalar_own", sae->tmp->own_commit_scalar);
	crypto_bignum_print("scalar_peer", sae->peer_commit_scalar);
	crypto_bignum_print("scalar_sum", tmp);

	/* IEEE Std 802.11-2016 is not exactly clear on the encoding of the bit
	 * string that is needed for KCK, PMK, and PMKID derivation, but it
	 * seems to make most sense to encode the
	 * (commit-scalar + peer-commit-scalar) mod r part as a bit string by
	 * zero padding it from left to the length of the order (in full
	 * octets). */
	crypto_bignum_to_bin(tmp, val, sizeof(val), sae->tmp->order_len);
	hexdump("SAE: PMKID", val, SAE_PMKID_LEN);
	if (sha256_prf(keyseed, sizeof(keyseed), "SAE KCK and PMK",
		       val, sae->tmp->order_len, keys, sizeof(keys)) < 0)
		goto fail;
	memset(keyseed, 0, sizeof(keyseed));
	memcpy(sae->tmp->kck, keys, SAE_KCK_LEN);
	memcpy(sae->pmk, keys + SAE_KCK_LEN, SAE_PMK_LEN);
	memcpy(sae->pmkid, val, SAE_PMKID_LEN);
	memset(keys, 0, sizeof(keys));
	hexdump("SAE: KCK", sae->tmp->kck, SAE_KCK_LEN);
	hexdump("SAE: PMK", sae->pmk, SAE_PMK_LEN);

	ret = 0;
fail:
	crypto_bignum_deinit(tmp, 0);
	return ret;
}


int sae_process_commit(struct sae_data *sae)
{
	uint8_t k[SAE_MAX_PRIME_LEN];
	if (sae->tmp == NULL ||
	    (sae->tmp->ec && sae_derive_k_ecc(sae, k) < 0) ||
	    /* (sae->tmp->dh && sae_derive_k_ffc(sae, k) < 0) || */
	    sae_derive_keys(sae, k) < 0)
		return -1;
	return 0;
}


void sae_write_commit(struct sae_data *sae, struct wpabuf *buf,
		      const struct wpabuf *token, const char *identifier)
{
	uint8_t *pos;

	if (sae->tmp == NULL)
		return;

	wpabuf_put_le16(buf, sae->group); /* Finite Cyclic Group */
	if (token) {
		wpabuf_put_buf(buf, token);
		hexdump("SAE: Anti-clogging token", wpabuf_head(token), wpabuf_len(token));
	}
	pos = wpabuf_put(buf, sae->tmp->prime_len);
	crypto_bignum_to_bin(sae->tmp->own_commit_scalar, pos,
			     sae->tmp->prime_len, sae->tmp->prime_len);
	hexdump("SAE: own commit-scalar", pos, sae->tmp->prime_len);
	if (sae->tmp->ec) {
		pos = wpabuf_put(buf, 2 * sae->tmp->prime_len);
		crypto_ec_point_to_bin(sae->tmp->ec,
				       sae->tmp->own_commit_element_ecc,
				       pos, pos + sae->tmp->prime_len);
		hexdump("SAE: own commit-element(x)",
			pos, sae->tmp->prime_len);
		hexdump("SAE: own commit-element(y)",
			pos + sae->tmp->prime_len, sae->tmp->prime_len);
	}
	/*
	 else {
		pos = wpabuf_put(buf, sae->tmp->prime_len);
		crypto_bignum_to_bin(sae->tmp->own_commit_element_ffc, pos,
				     sae->tmp->prime_len, sae->tmp->prime_len);
		hexdump("SAE: own commit-element",
			    pos, sae->tmp->prime_len);
	}
    */
	
	if (identifier) {
		/* Password Identifier element */
		wpabuf_put_u8(buf, WLAN_EID_EXTENSION);
		wpabuf_put_u8(buf, 1 + strlen(identifier));
		wpabuf_put_u8(buf, WLAN_EID_EXT_PASSWORD_IDENTIFIER);
		wpabuf_put_str(buf, identifier);
		fprintf(stderr, "SAE: own Password Identifier: %s\n",
			   identifier);
	}
}


uint16_t sae_group_allowed(struct sae_data *sae, int *allowed_groups, uint16_t group)
{
	if (allowed_groups) {
		int i;
		for (i = 0; allowed_groups[i] > 0; i++) {
			if (allowed_groups[i] == group)
				break;
		}
		if (allowed_groups[i] != group) {
			fprintf(stderr, "SAE: Proposed group %u not "
				   "enabled in the current configuration\n",
				   group);
			return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
		}
	}

	if (sae->state == SAE_COMMITTED && group != sae->group) {
		fprintf(stderr, "SAE: Do not allow group to be changed\n");
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}

	if (group != sae->group && sae_set_group(sae, group) < 0) {
		fprintf(stderr, "SAE: Unsupported Finite Cyclic Group %u\n",
			   group);
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}

	if (sae->tmp == NULL) {
		fprintf(stderr, "SAE: Group information not yet initialized\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (sae->tmp->dh && !allowed_groups) {
		fprintf(stderr, "SAE: Do not allow FFC group %u without "
			   "explicit configuration enabling it\n", group);
		return WLAN_STATUS_FINITE_CYCLIC_GROUP_NOT_SUPPORTED;
	}

	return WLAN_STATUS_SUCCESS;
}


static int sae_is_password_id_elem(const uint8_t *pos, const uint8_t *end)
{
	return end - pos >= 3 &&
		pos[0] == WLAN_EID_EXTENSION &&
		pos[1] >= 1 &&
		end - pos - 2 >= pos[1] &&
		pos[2] == WLAN_EID_EXT_PASSWORD_IDENTIFIER;
}


static void sae_parse_commit_token(struct sae_data *sae, const uint8_t **pos,
				   const uint8_t *end, const uint8_t **token,
				   size_t *token_len)
{
	size_t scalar_elem_len, tlen;
	const uint8_t *elem;

	if (token)
		*token = NULL;
	if (token_len)
		*token_len = 0;

	scalar_elem_len = (sae->tmp->ec ? 3 : 2) * sae->tmp->prime_len;
	if (scalar_elem_len >= (size_t) (end - *pos))
		return; /* No extra data beyond peer scalar and element */

	/* It is a bit difficult to parse this now that there is an
	 * optional variable length Anti-Clogging Token field and
	 * optional variable length Password Identifier element in the
	 * frame. We are sending out fixed length Anti-Clogging Token
	 * fields, so use that length as a requirement for the received
	 * token and check for the presence of possible Password
	 * Identifier element based on the element header information.
	 */
	tlen = end - (*pos + scalar_elem_len);

	if (tlen < SHA256_MAC_LEN) {
		fprintf(stderr,
			   "SAE: Too short optional data (%u octets) to include our Anti-Clogging Token\n",
			   (unsigned int) tlen);
		return;
	}

	elem = *pos + scalar_elem_len;
	if (sae_is_password_id_elem(elem, end)) {
		 /* Password Identifier element takes out all available
		  * extra octets, so there can be no Anti-Clogging token in
		  * this frame. */
		return;
	}

	elem += SHA256_MAC_LEN;
	if (sae_is_password_id_elem(elem, end)) {
		 /* Password Identifier element is included in the end, so
		  * remove its length from the Anti-Clogging token field. */
		tlen -= 2 + elem[1];
	}

	if (token)
		*token = *pos;
	if (token_len)
		*token_len = tlen;
	*pos += tlen;
}


static uint16_t sae_parse_commit_scalar(struct sae_data *sae, const uint8_t **pos,
				   const uint8_t *end)
{
	struct crypto_bignum *peer_scalar;

	if (sae->tmp->prime_len > end - *pos) {
		fprintf(stderr, "SAE: Not enough data for scalar\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	peer_scalar = crypto_bignum_init_set(*pos, sae->tmp->prime_len);
	if (peer_scalar == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	/*
	 * IEEE Std 802.11-2012, 11.3.8.6.1: If there is a protocol instance for
	 * the peer and it is in Authenticated state, the new Commit Message
	 * shall be dropped if the peer-scalar is identical to the one used in
	 * the existing protocol instance.
	 */
	if (sae->state == SAE_ACCEPTED && sae->peer_commit_scalar &&
	    crypto_bignum_cmp(sae->peer_commit_scalar, peer_scalar) == 0) {
		fprintf(stderr, "SAE: Do not accept re-use of previous "
			   "peer-commit-scalar\n");
		crypto_bignum_deinit(peer_scalar, 0);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	crypto_bignum_print("peer_scalar: ", peer_scalar);

	/* 1 < scalar < r */
	if (crypto_bignum_is_zero(peer_scalar) ||
	    crypto_bignum_is_one(peer_scalar) ||
	    crypto_bignum_cmp(peer_scalar, sae->tmp->order) >= 0) {
		fprintf(stderr, "SAE: Invalid peer scalar\n");
		crypto_bignum_deinit(peer_scalar, 0);
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}


	crypto_bignum_deinit(sae->peer_commit_scalar, 0);
	sae->peer_commit_scalar = peer_scalar;
	hexdump("SAE: Peer commit-scalar", *pos, sae->tmp->prime_len);
	*pos += sae->tmp->prime_len;

	return WLAN_STATUS_SUCCESS;
}


static uint16_t sae_parse_commit_element_ecc(struct sae_data *sae, const uint8_t **pos,
					const uint8_t *end)
{
	uint8_t prime[SAE_MAX_ECC_PRIME_LEN];

	if (2 * sae->tmp->prime_len > end - *pos) {
		fprintf(stderr, "SAE: Not enough data for "
			   "commit-element\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	if (crypto_bignum_to_bin(sae->tmp->prime, prime, sizeof(prime),
				 sae->tmp->prime_len) < 0)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	/* element x and y coordinates < p */
	if (memcmp(*pos, prime, sae->tmp->prime_len) >= 0 ||
	    memcmp(*pos + sae->tmp->prime_len, prime,
		      sae->tmp->prime_len) >= 0) {
		fprintf(stderr, "SAE: Invalid coordinates in peer "
			   "element\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	hexdump("SAE: Peer commit-element(x)", *pos, sae->tmp->prime_len);
	hexdump("SAE: Peer commit-element(y)", *pos + sae->tmp->prime_len, sae->tmp->prime_len);

	crypto_ec_point_deinit(sae->tmp->peer_commit_element_ecc, 0);
	sae->tmp->peer_commit_element_ecc =
		crypto_ec_point_from_bin(sae->tmp->ec, *pos);
	if (sae->tmp->peer_commit_element_ecc == NULL)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;

	if (!crypto_ec_point_is_on_curve(sae->tmp->ec,
					 sae->tmp->peer_commit_element_ecc)) {
		fprintf(stderr, "SAE: Peer element is not on curve\n");
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	*pos += 2 * sae->tmp->prime_len;

	return WLAN_STATUS_SUCCESS;
}

static uint16_t sae_parse_commit_element(struct sae_data *sae, const uint8_t **pos,
				    const uint8_t *end)
{
	/*
	 if (sae->tmp->dh)
		return sae_parse_commit_element_ffc(sae, pos, end);
	 */
	return sae_parse_commit_element_ecc(sae, pos, end);
}


static int sae_parse_password_identifier(struct sae_data *sae,
					 const uint8_t *pos, const uint8_t *end)
{

	if (!sae_is_password_id_elem(pos, end)) {
		if (sae->tmp->pw_id) {
			fprintf(stderr,
				   "SAE: No Password Identifier included, but expected one (%s)\n",
				   sae->tmp->pw_id);
			return WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER;
		}
		free(sae->tmp->pw_id);
		sae->tmp->pw_id = NULL;
		return WLAN_STATUS_SUCCESS; /* No Password Identifier */
	}

	if (sae->tmp->pw_id &&
	    (pos[1] - 1 != (int) strlen(sae->tmp->pw_id) ||
	     memcmp(sae->tmp->pw_id, pos + 3, pos[1] - 1) != 0)) {
		fprintf(stderr,
			   "SAE: The included Password Identifier does not match the expected one (%s)\n",
			   sae->tmp->pw_id);
		return WLAN_STATUS_UNKNOWN_PASSWORD_IDENTIFIER;
	}

	free(sae->tmp->pw_id);
	sae->tmp->pw_id = malloc(pos[1]);
	if (!sae->tmp->pw_id)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	memcpy(sae->tmp->pw_id, pos + 3, pos[1] - 1);
	sae->tmp->pw_id[pos[1] - 1] = '\0';

	return WLAN_STATUS_SUCCESS;
}


uint16_t sae_parse_commit(struct sae_data *sae, const uint8_t *data, size_t len,
		     const uint8_t **token, size_t *token_len, int *allowed_groups)
{
	const uint8_t *pos = data, *end = data + len;
	uint16_t res;

	/* Check Finite Cyclic Group */
	if (end - pos < 2)
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	res = sae_group_allowed(sae, allowed_groups, WPA_GET_LE16(pos));
	if (res != WLAN_STATUS_SUCCESS)
		return res;
	pos += 2;

	/* Optional Anti-Clogging Token */
	sae_parse_commit_token(sae, &pos, end, token, token_len);

	/* commit-scalar */
	res = sae_parse_commit_scalar(sae, &pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/* commit-element */
	res = sae_parse_commit_element(sae, &pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/* Optional Password Identifier element */
	res = sae_parse_password_identifier(sae, pos, end);
	if (res != WLAN_STATUS_SUCCESS)
		return res;

	/*
	 * Check whether peer-commit-scalar and PEER-COMMIT-ELEMENT are same as
	 * the values we sent which would be evidence of a reflection attack.
	 */
	if (!sae->tmp->own_commit_scalar ||
	    crypto_bignum_cmp(sae->tmp->own_commit_scalar,
			      sae->peer_commit_scalar) != 0 ||
	    /*(sae->tmp->dh &&
	     (!sae->tmp->own_commit_element_ffc ||
	      crypto_bignum_cmp(sae->tmp->own_commit_element_ffc,
				sae->tmp->peer_commit_element_ffc) != 0)) || */
	    (sae->tmp->ec &&
	     (!sae->tmp->own_commit_element_ecc ||
	      crypto_ec_point_cmp(sae->tmp->ec,
				  sae->tmp->own_commit_element_ecc,
				  sae->tmp->peer_commit_element_ecc) != 0)))
		return WLAN_STATUS_SUCCESS; /* scalars/elements are different */

	/*
	 * This is a reflection attack - return special value to trigger caller
	 * to silently discard the frame instead of replying with a specific
	 * status code.
	 */
	return SAE_SILENTLY_DISCARD;
}


static void sae_cn_confirm(struct sae_data *sae, const uint8_t *sc,
			   const struct crypto_bignum *scalar1,
			   const uint8_t *element1, size_t element1_len,
			   const struct crypto_bignum *scalar2,
			   const uint8_t *element2, size_t element2_len,
			   uint8_t *confirm)
{
	const uint8_t *addr[5];
	size_t len[5];
	uint8_t scalar_b1[SAE_MAX_PRIME_LEN], scalar_b2[SAE_MAX_PRIME_LEN];

	/* Confirm
	 * CN(key, X, Y, Z, ...) =
	 *    HMAC-SHA256(key, D2OS(X) || D2OS(Y) || D2OS(Z) | ...)
	 * confirm = CN(KCK, send-confirm, commit-scalar, COMMIT-ELEMENT,
	 *              peer-commit-scalar, PEER-COMMIT-ELEMENT)
	 * verifier = CN(KCK, peer-send-confirm, peer-commit-scalar,
	 *               PEER-COMMIT-ELEMENT, commit-scalar, COMMIT-ELEMENT)
	 */
	addr[0] = sc;
	len[0] = 2;
	crypto_bignum_to_bin(scalar1, scalar_b1, sizeof(scalar_b1),
			     sae->tmp->prime_len);
	addr[1] = scalar_b1;
	len[1] = sae->tmp->prime_len;
	addr[2] = element1;
	len[2] = element1_len;
	crypto_bignum_to_bin(scalar2, scalar_b2, sizeof(scalar_b2),
			     sae->tmp->prime_len);
	addr[3] = scalar_b2;
	len[3] = sae->tmp->prime_len;
	addr[4] = element2;
	len[4] = element2_len;
	hmac_sha256_vector(sae->tmp->kck, sizeof(sae->tmp->kck), 5, addr, len,
			   confirm);
}


static void sae_cn_confirm_ecc(struct sae_data *sae, const uint8_t *sc,
			       const struct crypto_bignum *scalar1,
			       const struct crypto_ec_point *element1,
			       const struct crypto_bignum *scalar2,
			       const struct crypto_ec_point *element2,
			       uint8_t *confirm)
{
	uint8_t element_b1[2 * SAE_MAX_ECC_PRIME_LEN];
	uint8_t element_b2[2 * SAE_MAX_ECC_PRIME_LEN];

	crypto_ec_point_to_bin(sae->tmp->ec, element1, element_b1,
			       element_b1 + sae->tmp->prime_len);
	crypto_ec_point_to_bin(sae->tmp->ec, element2, element_b2,
			       element_b2 + sae->tmp->prime_len);

	sae_cn_confirm(sae, sc, scalar1, element_b1, 2 * sae->tmp->prime_len,
		       scalar2, element_b2, 2 * sae->tmp->prime_len, confirm);
}


void sae_write_confirm(struct sae_data *sae, struct wpabuf *buf)
{
	const uint8_t *sc;

	if (sae->tmp == NULL)
		return;

	/* Send-Confirm */
	sc = wpabuf_put(buf, 0);
	wpabuf_put_le16(buf, sae->send_confirm);
	if (sae->send_confirm < 0xffff)
		sae->send_confirm++;

	if (sae->tmp->ec)
		sae_cn_confirm_ecc(sae, sc, sae->tmp->own_commit_scalar,
				   sae->tmp->own_commit_element_ecc,
				   sae->peer_commit_scalar,
				   sae->tmp->peer_commit_element_ecc,
				   wpabuf_put(buf, SHA256_MAC_LEN));
	/*
	 else
		sae_cn_confirm_ffc(sae, sc, sae->tmp->own_commit_scalar,
				   sae->tmp->own_commit_element_ffc,
				   sae->peer_commit_scalar,
				   sae->tmp->peer_commit_element_ffc,
				   wpabuf_put(buf, SHA256_MAC_LEN));
	*/
}


int sae_check_confirm(struct sae_data *sae, const uint8_t *data, size_t len)
{
	uint8_t verifier[SHA256_MAC_LEN];

	if (len < 2 + SHA256_MAC_LEN) {
		fprintf(stderr, "SAE: Too short confirm message\n");
		return -1;
	}

	// fprintf(stderr, "SAE: peer-send-confirm %u\n", WPA_GET_LE16(data));

	if (!sae->tmp || !sae->peer_commit_scalar ||
	    !sae->tmp->own_commit_scalar) {
		fprintf(stderr, "SAE: Temporary data not yet available\n");
		return -1;
	}

	if (sae->tmp->ec) {
		if (!sae->tmp->peer_commit_element_ecc ||
		    !sae->tmp->own_commit_element_ecc)
			return -1;
		sae_cn_confirm_ecc(sae, data, sae->peer_commit_scalar,
				   sae->tmp->peer_commit_element_ecc,
				   sae->tmp->own_commit_scalar,
				   sae->tmp->own_commit_element_ecc,
				   verifier);
	}
	/*
	else {
		if (!sae->tmp->peer_commit_element_ffc ||
		    !sae->tmp->own_commit_element_ffc)
			return -1;
		sae_cn_confirm_ffc(sae, data, sae->peer_commit_scalar,
				   sae->tmp->peer_commit_element_ffc,
				   sae->tmp->own_commit_scalar,
				   sae->tmp->own_commit_element_ffc,
				   verifier);
	}
	*/

	if (const_time_memcmp(verifier, data + 2, SHA256_MAC_LEN) != 0) {
		fprintf(stderr, "SAE: Confirm mismatch\n");
		hexdump("SAE: Received confirm",
			data + 2, SHA256_MAC_LEN);
		hexdump("SAE: Calculated verifier",
			verifier, SHA256_MAC_LEN);
		return -1;
	}

	return 0;
}
