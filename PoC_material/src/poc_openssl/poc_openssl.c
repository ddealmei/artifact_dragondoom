#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define COORD_LEN 32
#define NID_P256 415

typedef struct {
    EC_POINT* p;
    EC_GROUP* group;
    BN_CTX* ctx;
} openssl_params;


int do_test(BIGNUM *x, openssl_params *params, uint8_t compression_fmt) {
    return EC_POINT_set_compressed_coordinates_GFp(params->group, params->p, x, compression_fmt, params->ctx);
}


int main(int argc, char **argv) {
    BIGNUM* x = NULL;
    openssl_params* params = NULL;
    uint8_t* buff = NULL;
    if (argc != 3) {
        fprintf(stderr, "Expected x coordinate and seed_parity in args.\n");
        exit(1);
    }
    if (BN_hex2bn(&x, argv[1]) != 2*COORD_LEN) {
        fprintf(stderr, "error while parsing x coordinate\n");
        goto end;
    }
    uint8_t seed_parity = atoi(argv[2]) & 1;

    /* Get curve P256 and init contexts */
    params = malloc(sizeof(openssl_params));
    if (params == NULL)
        goto end;
    params->group = EC_GROUP_new_by_curve_name(NID_P256);
    params->ctx = BN_CTX_new();
    params->p = EC_POINT_new(params->group);
    
    /* Perform the test */
    if (do_test(x, params, seed_parity) == 0)
        fprintf(stderr, "error during point decompression\n");

end:
    if (x) BN_free(x);
    if (params) {
        if (params->p) EC_POINT_free(params->p);
        if (params->ctx) BN_CTX_free(params->ctx);
        if (params->group) EC_GROUP_free(params->group);
        free(params);
    }
    if (buff) free(buff);
    return 0;
}
