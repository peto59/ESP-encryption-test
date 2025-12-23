#pragma once

#include "mbedtls/cipher.h"
#include "mbedtls/platform_util.h"
#include <stddef.h>

struct aes_handle{
	mbedtls_cipher_context_t ctx;
};

typedef struct aes_handle aes_handle_t;

int aes_fini(void *handle);
int aes_init(void *handle);
int aes_set_key(void *handle, const unsigned char *key, size_t klen);
int aes_set_iv(void *handle, const unsigned char *iv, size_t ivlen);
int aes_crypt(void *handle, const unsigned char *in, size_t ilen, unsigned char *out, size_t *olen);
void aes_secure_zeroize(void *data, size_t len);
