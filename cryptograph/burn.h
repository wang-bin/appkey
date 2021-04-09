#ifndef BURN_H
#define BURN_H

#include <stddef.h>


#if defined(HAVE_MEMSET_S)

#include <string.h>
static inline void burn(void *dest, size_t len) { memset_s(dest, len, 0, len); }

#elif defined(HAVE_EXPLICIT_BZERO)

#include <string.h>
static inline void burn(void *dest, size_t len) { explicit_bzero(dest, len); }

#else

static inline void burn(void *dest, size_t len)
{
	volatile uint8_t *p = (uint8_t *)dest;
	const uint8_t *end = (uint8_t *)dest+len;

	while (p < end) *p++ = 0;
}

#endif


#endif
