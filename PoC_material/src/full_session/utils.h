#ifndef DRAGONFLY_UTILS_H
#define DRAGONFLY_UTILS_H

#include <stdint.h>
#include <stdio.h>

// #define DEBUG 1

static inline void WPA_PUT_LE16(uint8_t *a, uint16_t val)
{
    a[1] = val >> 8;
    a[0] = val & 0xff;
}

static inline uint16_t WPA_GET_LE16(const uint8_t *a)
{
	return (a[1] << 8) | a[0];
}

static inline void hexdump(const char * label, const uint8_t *buff, size_t len)
{
#ifdef DEBUG
	fprintf(stderr, "%s: ", label);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02X", buff[i] & 0xFF);
    fprintf(stderr, "\n");
#endif
}

#endif //DRAGONFLY_UTILS_H
