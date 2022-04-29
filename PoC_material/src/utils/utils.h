#ifndef UTILS_H

#define UTILS_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

#define TESTS_PER_POINT 100 
#define POINTS_TO_TEST 500
#define TOTAL_TESTS TESTS_PER_POINT*POINTS_TO_TEST
#define COORD_LEN 32
#define NID_P256 415

/* Conversion functions */
// int wolfssl2openssl_params

size_t ec_get_random_x_bin(uint8_t** buff);
uint8_t get_y_parity(uint8_t* buff, size_t len, int nid);


// int EC_get_random_x(BIGNUM** x);
// void EC_get_random_x_openssl(char** buf);
// size_t EC_get_random_x_iwd(uint8_t** buf);
void get_random_choices(uint8_t* buf, size_t len, size_t n_parity[2]);
uint64_t rdtsc();
size_t min(size_t array[2][2]);
double get_avg(uint64_t* times, size_t n);
void print_point_coordinates_openssl(EC_POINT* point, EC_GROUP* group);
void print_summary(size_t indexes[2][2], uint64_t res_y_odd[2][TOTAL_TESTS], uint64_t res_y_even[2][TOTAL_TESTS]);
void print_summary_to_file(char* filename, size_t indexes[2][2], uint64_t res_y_odd[2][TOTAL_TESTS], uint64_t res_y_even[2][TOTAL_TESTS]);


#endif