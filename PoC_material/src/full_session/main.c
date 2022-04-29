/* This file only contains some structure instanciation and tests to see if
 * everything is working as intended.
 * None of the following code needs to be implemented in HaCl*
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "sae.h"
#include "wpabuf.h"
#include "crypto.h"

static struct wpabuf * auth_build_sae_commit(struct sae_data *sae, char *pwd, char *pwd_id, uint8_t *macA, uint8_t *macB)
{
    struct wpabuf *buf;
    const char *rx_id = NULL;

    if (sae->tmp)
        rx_id = sae->tmp->pw_id;
    else
        rx_id = pwd_id;

    if (!pwd) {
        fprintf(stderr, "SAE: No password available");
        return NULL;
    }

    if ( sae_prepare_commit(macA, macB,
                           (uint8_t*) pwd, strlen(pwd), rx_id, sae) < 0) {
        fprintf(stderr, "SAE: Could not pick PWE");
        return NULL;
    }

    buf = wpabuf_alloc(SAE_COMMIT_MAX_LEN +
                       (rx_id ? 3 + strlen(rx_id) : 0));
    if (buf == NULL)
        return NULL;
    sae_write_commit(sae, buf, sae->tmp ?
                                    sae->tmp->anti_clogging_token : NULL, rx_id);

    return buf;
}


static int sae_test_custom(int group_id, char* pwd, uint8_t *mac_A, uint8_t *mac_B) {
	int err = -1;
	struct sae_data* saeA;
	struct wpabuf* commitA = NULL;
	struct wpabuf* confirmA = NULL;

	saeA = malloc(sizeof(*saeA));
	if (saeA == NULL) {
		fprintf(stderr, "allocation failure\n");
		goto end;
	}
	memset(saeA, 0, sizeof(*saeA));

	// Set the group
	err = sae_set_group(saeA, group_id);
	if (err) goto end;

	// Compute the commit message
	commitA = auth_build_sae_commit(saeA, pwd, NULL, mac_A, mac_B);
	if (commitA == NULL) goto end;

end:
	if (saeA) {sae_clear_data(saeA); free(saeA);}
	if (commitA) wpabuf_free(commitA);
	if (confirmA) wpabuf_free(confirmA);

	return err;
}

void parseTrace(char *str, char *pwd, uint8_t *macA, uint8_t *macB) {
	uint64_t tmp;

	// First field is the address A
	tmp = strtol(str, &str, 16);
	for (int i = 5; i >= 0; --i)
	{
		macA[i] = (uint8_t) tmp & 0XFF;
		tmp = tmp >> 8;
	}
	str++;
	
	// Second field is the address B
	tmp = strtol(str, &str, 16);
	for (int i = 5; i >= 0; --i)
	{
		macB[i] = (uint8_t) tmp & 0XFF;
		tmp = tmp >> 8;
	}
	str++;

memcpy(pwd, str, strlen(str));
}

int main(int argc, char** argv) {
	int err;
	if (argc < 2) {
		fprintf(stderr, "expect a macA,macB,pwd\n");
		return -1;
	}

	int group_id = 19;
	uint8_t mac_A[6] = { 0x98, 0xe7, 0x43, 0xd8, 0x6f, 0xbd };
	uint8_t mac_B[6] = { 0x04, 0xed, 0x33, 0xc0, 0x85, 0x9b };
	char pwd[64] = {0};

	for(int i = 1; i < argc; i++) {
		memset(pwd,0, 64);
		parseTrace(argv[i], pwd, mac_A, mac_B);
		for(int j = 0; j < 6; j++)
			printf("%02x",mac_A[j]);
		printf(",");
		for(int j = 0; j < 6; j++)
			printf("%02x",mac_B[j]);
		printf(",%s \t", pwd);
		err = sae_test_custom(group_id, pwd, mac_A, mac_B);
		if( err != 0) {
			fprintf(stderr, "unexpected error code %d\n", err);
		}
	}	
	return err;
}