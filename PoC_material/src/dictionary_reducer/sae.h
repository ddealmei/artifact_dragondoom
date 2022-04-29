/*
 * Simultaneous authentication of equals
 * Copyright (c) 2012-2013, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef SAE_H
#define SAE_H

#include <stdint.h>

/* This is defined in hostapd to represent the size of a MAC address */
#define ETH_ALEN 6

#define SAE_KCK_LEN 32
#define SAE_PMK_LEN 32
#define SAE_PMKID_LEN 16
#define SAE_KEYSEED_KEY_LEN 32
#define SAE_MAX_PRIME_LEN 512
#define SAE_MAX_ECC_PRIME_LEN 66
#define SAE_COMMIT_MAX_LEN (2 + 3 * SAE_MAX_PRIME_LEN)
#define SAE_CONFIRM_MAX_LEN (2 + SAE_MAX_PRIME_LEN)

/* Special value returned by sae_parse_commit() */
#define SAE_SILENTLY_DISCARD 65535

struct sae_temporary_data {
    /* SECRETS */
	uint8_t kck[SAE_KCK_LEN];
	struct crypto_bignum *own_commit_scalar;
	// struct crypto_bignum *own_commit_element_ffc;
	struct crypto_ec_point *own_commit_element_ecc;
	// struct crypto_bignum *peer_commit_element_ffc;
	struct crypto_ec_point *peer_commit_element_ecc;
	struct crypto_ec_point *pwe_ecc;
	// struct crypto_bignum *pwe_ffc;
	/* PUBLIC */
	struct crypto_bignum *sae_rand;
	struct crypto_ec *ec;
	int prime_len;
	int order_len;
	const struct dh_group *dh;
	const struct crypto_bignum *prime;
	const struct crypto_bignum *order;
	struct crypto_bignum *prime_buf;
	struct crypto_bignum *order_buf;
	struct wpabuf *anti_clogging_token;
	char *pw_id;
	int vlan_id;
	uint8_t bssid[ETH_ALEN];
};

enum sae_state {
	SAE_NOTHING, SAE_COMMITTED, SAE_CONFIRMED, SAE_ACCEPTED
};

struct sae_data {
	enum sae_state state;
	uint16_t send_confirm;
	uint8_t pmk[SAE_PMK_LEN];   /* SECRET */
	uint8_t pmkid[SAE_PMKID_LEN];   /* PUBLIC ? */
	struct crypto_bignum *peer_commit_scalar;   /* PUBLIC */
	int group;
	unsigned int sync; /* protocol instance variable: Sync */
	uint16_t rc; /* protocol instance variable: Rc (received send-confirm) */
	struct sae_temporary_data *tmp; /* contains both SECRET and PUBLIC informations */
};

/**
 * Get the group parameters from its id 
 * @param sae Data structure to store the group parameters -  Only PUBLIC elements are used in this function
 * @param group - PUBLIC
 * @return
 */
int sae_set_group(struct sae_data *sae, int group);
void sae_clear_temp_data(struct sae_data *sae);
void sae_clear_data(struct sae_data *sae);

bool sae_derive_pwe_ecc(struct sae_data* sae, const uint8_t* addr1,
	const uint8_t* addr2, const uint8_t* password,
	size_t password_len, const char* identifier);

#endif /* SAE_H */