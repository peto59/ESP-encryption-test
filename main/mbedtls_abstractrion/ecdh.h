#pragma once

#include "mbedtls/ecdh.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ecp.h"

struct ecdh_handle{
    mbedtls_ecdh_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
}

typedef struct ecdh_handle ecdh_handle_t;

int ecdh_init(void *handle);
int ecdh_get_pubkey(void *handle, unsigned char *out, size_t *olen);
int ecdh_import_pubkey(void *handle, const unsigned char *in, size_t ilen);
int ecdh_get_key(void *handle, unsigned char *out, size_t *olen);
int ecdh_fini(void *handle);
