#pragma once

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include <stddef.h>

int hkdf_transform(void *handle, const unsigned char *in, size_t ilen, unsigned char *out, size_t *olen);
