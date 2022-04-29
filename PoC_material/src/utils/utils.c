#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "utils.h"

size_t min(size_t array[2][2]) {
  size_t out = array[0][0];
  if (array[0][1] < out) out = array[0][1];
  if (array[1][0] < out) out = array[1][0];
  if (array[1][1] < out) out = array[1][1];
  return out;
}

double get_avg(uint64_t *times, size_t n) {
  uint64_t avg = 0;
  for (int i = 0; i < n; ++i)
    avg += times[i];
  return (double) avg/n;
}

uint64_t rdtsc() {
  uint64_t a, d;
  asm volatile ("mfence");
  asm volatile ("rdtsc" : "=a" (a), "=d" (d));
  a = (d<<32) | a;
  asm volatile ("mfence");
  return a;
}

void get_random_choices(uint8_t *buf, size_t len, size_t n_parity[2]) {
  n_parity[0] = 0;
  n_parity[1] = 0;

	for(size_t i = 0; i < len; ++i){
		buf[i] = (uint8_t) (rand() & 1);
		n_parity[buf[i]] += 1;
	}
}

int EC_get_random_x(BIGNUM **x) {
    int ok = 0;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *P = EC_POINT_new(group);
 	  BN_CTX *ctx = BN_CTX_new();
    BIGNUM *k; 
  
    k = BN_new();

    if (!EC_GROUP_get_order(group, k, ctx)) goto err;
    if (!BN_pseudo_rand(k, BN_num_bits(k), 0, 0)) goto err;
    if (!EC_POINT_mul(group, P, k, NULL, NULL, ctx)) goto err;

    BIGNUM *y = BN_new();
    if (!EC_POINT_get_affine_coordinates_GFp(group, P, *x, y, NULL)) goto err;
    

    ok = 1;
err:
    if (k) BN_free(k);
    if (y) BN_free(y);
    if (ctx != NULL) BN_CTX_free(ctx);
    if (group) EC_GROUP_free(group);
    if (P) EC_POINT_free(P);

    return ok; 
}    

// void EC_get_random_x_openssl(char **buff) {
//   BIGNUM *x = BN_new();

//   EC_get_random_x(&x);
//   *buff = BN_bn2hex(x);

//   if (x) BN_free(x);

//   return;
// }

size_t ec_get_random_x_bin(uint8_t** buff) {
  BIGNUM *x = BN_new();

  EC_get_random_x(&x);
  if (*buff == NULL) *buff = malloc(BN_num_bytes(x));
  size_t len = BN_bn2bin(x, *buff);

  if (x) BN_free(x);

  return len;
}

uint8_t get_y_parity(uint8_t* buff, size_t len, int nid) {
      BN_CTX *ctx = BN_CTX_new();
      uint8_t ret;
      BIGNUM *tmp1 = NULL, *tmp2 = NULL, *x_ = NULL, *x = NULL, *y = NULL;
      BN_CTX_start(ctx);
      tmp1 = BN_CTX_get(ctx);
      tmp2 = BN_CTX_get(ctx);
      x = BN_CTX_get(ctx);
      y = BN_CTX_get(ctx);
      if (y == NULL)
          goto err;

      BIGNUM *field = BN_CTX_get(ctx); 
      BIGNUM *a = BN_CTX_get(ctx), *b = BN_CTX_get(ctx);
      EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      EC_GROUP_get_curve(group, field, a, b, ctx);

      x_ = BN_bin2bn(buff, len, x_);

      /*-
      * Recover y.  We have a Weierstrass equation
      *     y^2 = x^3 + a*x + b,
      * so  y  is one of the square roots of  x^3 + a*x + b.
      */

      /* tmp1 := x^3 */
      if (!BN_nnmod(x, x_, field, ctx))
          goto err;
      if (!BN_mod_sqr(tmp2, x_, field, ctx))
          goto err;
      if (!BN_mod_mul(tmp1, tmp2, x_, field, ctx))
          goto err;
      /* tmp1 := tmp1 + a*x */
      if (!BN_mod_mul(tmp2, a, x, field, ctx))
          goto err;
      if (!BN_mod_add(tmp1, tmp1, tmp2, field, ctx))
          goto err; 
      /* tmp1 := tmp1 + b */
      if (!BN_mod_add_quick(tmp1, tmp1, b, field))
          goto err;
      if (!BN_mod_sqrt(y, tmp1, field, ctx))
          goto err;

      ret = BN_is_odd(y) ? 1 : 0;
  err:
      if (ctx) BN_CTX_free(ctx);
      if (group) EC_GROUP_free(group);
      if (x_) BN_free(x_);

      return ret;
  }

void print_summary(size_t indexes[2][2], uint64_t res_y_odd[2][TOTAL_TESTS], uint64_t res_y_even[2][TOTAL_TESTS]) {
    size_t min_index = min(indexes);
    // printf("#     seed_0-y_0   seed_0-y_1   seed_1-y_0   seed_1-y_1\n");
    for (int i = 0; i < min_index; ++i)
    {
        // bit_0-y_0 bit_0-y_1 bit_1-y_0 bit_1-y_1
        printf("  %12lu %12lu %12lu %12lu\n", res_y_even[0][i], res_y_odd[0][i], res_y_even[1][i], res_y_odd[1][i]);
    }
    printf("# average:\n");
    double avg_0_0 = get_avg(res_y_even[0], min_index);
    double avg_0_1 = get_avg(res_y_even[1], min_index);
    double avg_1_0 = get_avg(res_y_odd[0], min_index);
    double avg_1_1 = get_avg(res_y_odd[1], min_index);
    printf("# %12.2lf %12.2lf %12.2lf %12.2lf\n", avg_0_0, avg_0_1, avg_1_0, avg_1_1);
}

void print_summary_to_file(char *filename, size_t indexes[2][2], uint64_t res_y_odd[2][TOTAL_TESTS],  uint64_t res_y_even[2][TOTAL_TESTS]) {
  FILE *fp = fopen(filename, "a");
  size_t min_index = min(indexes);
  // printf("#     seed_0-y_0   seed_0-y_1   seed_1-y_0   seed_1-y_1\n");
  for (int i = 0; i < min_index; ++i)     {
    // bit_0-y_0 bit_0-y_1 bit_1-y_0 bit_1-y_1
    fprintf(fp, "  %12lu %12lu %12lu %12lu\n", res_y_even[0][i], res_y_odd[0][i], res_y_even[1][i], res_y_odd[1][i]);
  }
  fclose(fp);
  printf("# average:\n");
  double avg_0_0 = get_avg(res_y_even[0], min_index);
  double avg_0_1 = get_avg(res_y_even[1], min_index);
  double avg_1_0 = get_avg(res_y_odd[0], min_index);
  double avg_1_1 = get_avg(res_y_odd[1], min_index);
  printf("# %12.2lf %12.2lf %12.2lf %12.2lf\n", avg_0_0, avg_0_1, avg_1_0, avg_1_1);
}

void print_point_coordinates_openssl(EC_POINT *point, EC_GROUP *group) {
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if (EC_POINT_get_affine_coordinates_GFp(group, point, x, y, NULL)) {
        BN_print_fp(stdout, x);
        putc('\n', stdout);
        BN_print_fp(stdout, y);
        putc('\n', stdout);
    }

    BN_free(x);
    BN_free(y);
}
