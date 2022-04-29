/*
 * Dynamic data buffer
 * Copyright (c) 2007-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "wpabuf.h"


static void wpabuf_overflow(const struct wpabuf *buf, size_t len)
{
	fprintf(stderr, "wpabuf %p (size=%lu used=%lu) overflow len=%lu",
		   buf, (unsigned long) buf->size, (unsigned long) buf->used,
		   (unsigned long) len);
	abort();
}

/**
 * wpabuf_alloc - Allocate a wpabuf of the given size
 * @len: Length for the allocated buffer
 * Returns: Buffer to the allocated wpabuf or %NULL on failure
 */
struct wpabuf * wpabuf_alloc(size_t len)
{
	struct wpabuf *buf = malloc(sizeof(struct wpabuf) + len);
	memset(buf, 0, sizeof(struct wpabuf) + len);
	if (buf == NULL)
		return NULL;

	buf->size = len;
	buf->buf = (uint8_t *) (buf + 1);
	return buf;
}



/**
 * wpabuf_free - Free a wpabuf
 * @buf: wpabuf buffer
 */
void wpabuf_free(struct wpabuf *buf)
{
	if (buf == NULL)
		return;
	if (buf->flags & WPABUF_FLAG_EXT_DATA)
		free(buf->buf);
	free(buf);
}

void * wpabuf_put(struct wpabuf *buf, size_t len)
{
	void *tmp = wpabuf_mhead_u8(buf) + wpabuf_len(buf);
	buf->used += len;
	if (buf->used > buf->size) {
		wpabuf_overflow(buf, len);
	}
	return tmp;
}