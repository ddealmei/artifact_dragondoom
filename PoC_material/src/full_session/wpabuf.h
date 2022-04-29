/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WPABUF_H
#define WPABUF_H

#include <stdint.h>
#include "utils.h"

#define BIT(x) (1U << (x))
/* wpabuf::buf is a pointer to external data */
#define WPABUF_FLAG_EXT_DATA BIT(0)

/*
 * Internal data structure for wpabuf. Please do not touch this directly from
 * elsewhere. This is only defined in header file to allow inline functions
 * from this file to access data.
 */
struct wpabuf {
	size_t size; /* total size of the allocated buffer */
	size_t used; /* length of data in the buffer */
	uint8_t *buf; /* pointer to the head of the buffer */
	unsigned int flags;
	/* optionally followed by the allocated buffer */
};

struct wpabuf * wpabuf_alloc(size_t len);
void wpabuf_free(struct wpabuf *buf);
void * wpabuf_put(struct wpabuf *buf, size_t len);

/**
 * wpabuf_len - Get the current length of a wpabuf buffer data
 * @buf: wpabuf buffer
 * Returns: Currently used length of the buffer
 */
static inline size_t wpabuf_len(const struct wpabuf *buf)
{
	return buf->used;
}

/**
 * wpabuf_head - Get pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline const void * wpabuf_head(const struct wpabuf *buf)
{
	return buf->buf;
}

/**
 * wpabuf_mhead - Get modifiable pointer to the head of the buffer data
 * @buf: wpabuf buffer
 * Returns: Pointer to the head of the buffer data
 */
static inline void * wpabuf_mhead(struct wpabuf *buf)
{
	return buf->buf;
}

static inline uint8_t * wpabuf_mhead_u8(struct wpabuf *buf)
{
	return (uint8_t *) wpabuf_mhead(buf);
}

static inline void wpabuf_put_u8(struct wpabuf *buf, uint8_t data)
{
	uint8_t *pos = (uint8_t *) wpabuf_put(buf, 1);
	*pos = data;
}

static inline void wpabuf_put_le16(struct wpabuf *buf, uint16_t data)
{
	uint8_t *pos = (uint8_t *) wpabuf_put(buf, 2);
	WPA_PUT_LE16(pos, data);
}

static inline void wpabuf_put_data(struct wpabuf *buf, const void *data,
				   size_t len)
{
	if (data)
		memcpy(wpabuf_put(buf, len), data, len);
}

static inline void wpabuf_put_buf(struct wpabuf *dst,
				  const struct wpabuf *src)
{
	wpabuf_put_data(dst, wpabuf_head(src), wpabuf_len(src));
}

static inline void wpabuf_put_str(struct wpabuf *dst, const char *str)
{
	wpabuf_put_data(dst, str, strlen(str));
}

#endif /* WPABUF_H */
