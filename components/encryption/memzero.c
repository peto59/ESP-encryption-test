#ifdef USE_SECURE_ZEROIZE_SW

#include "memzero.h"

static inline void memzero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) {
        *vp++ = 0;
    }
}


#endif
