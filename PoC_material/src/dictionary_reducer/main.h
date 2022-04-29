#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t A[6];
    uint8_t B[6];
    bool same_parity;
} Trace;

#endif
