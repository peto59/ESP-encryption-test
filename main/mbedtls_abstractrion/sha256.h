#pragma once

#include "mbedtls/sha256.h"

int sha256_calc(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen);
