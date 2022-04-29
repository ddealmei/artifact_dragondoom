/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2016, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <utils.h>

#include "const_time.h"
#include "crypto.h"
#include "sha256.h"
#include "sae.h"

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
    return group == 19;
}

int dragonfly_is_quadratic_residue_blind(struct crypto_ec *ec,
                                         const struct crypto_bignum *val)
{
    // struct crypto_bignum *r, *num, *qr_or_qnr = NULL;
    int res = -1;
    const struct crypto_bignum *prime;

    prime = crypto_ec_get_prime(ec);
    res = crypto_bignum_legendre(val, prime);
    if (res == -2) {
        res = -1;
    }
    return res == 1;
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
 * @param pwd_value - SECRET
 * @return
 */
static int sae_test_pwd_seed_ecc(struct sae_data *sae, const uint8_t *pwd_seed,
				 const uint8_t *prime, uint8_t *pwd_value)
{
	struct crypto_bignum *y_sqr, *x_cand;
	int res;
	size_t bits;
	int cmp_prime;
	unsigned int in_range;

	/* pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p) */
	bits = crypto_ec_prime_len_bits(sae->tmp->ec);
	if (sha256_prf_bits(pwd_seed, SHA256_MAC_LEN, "SAE Hunting and Pecking",
			    prime, sae->tmp->prime_len, pwd_value, bits) < 0)
		return -1;
	/* shift the buffer to be the appropriate bit-length if needed */
	if (bits % 8)
		buf_shift_right(pwd_value, sae->tmp->prime_len, 8 - bits % 8);

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

	res = dragonfly_is_quadratic_residue_blind(sae->tmp->ec, y_sqr);
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
bool sae_derive_pwe_ecc(struct sae_data *sae, const uint8_t *addr1,
			      const uint8_t *addr2, const uint8_t *password,
			      size_t password_len, const char *identifier)
{
	uint8_t counter;
	uint8_t addrs[2 * ETH_ALEN];
	const uint8_t *addr[3];
	size_t len[3];
	size_t num_elem;
	int pwd_seed_odd = 0;
	uint8_t prime[SAE_MAX_ECC_PRIME_LEN];
	size_t prime_len;
	struct crypto_bignum *qr = NULL, *qnr = NULL;
	uint8_t x_bin[SAE_MAX_ECC_PRIME_LEN];
	int res = -1;
	uint8_t found = 0; /* 0 (false) or 0xff (true) to be used as const_time_*
		       * mask */

	memset(x_bin, 0, sizeof(x_bin));

	prime_len = sae->tmp->prime_len;
	if (crypto_bignum_to_bin(sae->tmp->prime, prime, sizeof(prime),
				 prime_len) < 0)
		goto fail;
	/*
	 * H(salt, ikm) = HMAC-SHA256(salt, ikm)
	 * base = password [|| identifier]
	 * pwd-seed = H(MAX(STA-A-MAC, STA-B-MAC) || MIN(STA-A-MAC, STA-B-MAC),
	 *              base || counter)
	 */
	sae_pwd_seed_key(addr1, addr2, addrs);

	addr[0] = password;
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
	for (counter = 1; !found; counter++) {
		uint8_t pwd_seed[SHA256_MAC_LEN];
		if (hmac_sha256_vector(addrs, sizeof(addrs), num_elem,
				       addr, len, pwd_seed) < 0)
			break;

		res = sae_test_pwd_seed_ecc(sae, pwd_seed, prime, x_bin);
		pwd_seed_odd = pwd_seed[SHA256_MAC_LEN - 1] & 0x01;
		memset(pwd_seed, 0, sizeof(pwd_seed));
		if (res < 0)
			goto fail;
		
		found |= res * 0xff;
	}

	if (!found) {
		res = -1;
		goto fail;
	}
	
	int out = get_y_parity(x_bin, COORD_LEN, NID_P256) == pwd_seed_odd;
fail:
	crypto_bignum_deinit(qr, 0);
	crypto_bignum_deinit(qnr, 0);
	memset(x_bin, 0, sizeof(x_bin));

	return out;
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
