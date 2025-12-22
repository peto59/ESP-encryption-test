#include "aes.h"


int aes_fini(void *handle){
	aes_handle_t *h = (aes_handle_t *)handle;
	mbedtls_cipher_free(&ctx);
	return 0;
}

int aes_init(void *handle){
	aes_handle_t *h = (aes_handle_t *)handle;
	int ret = -1;
    mbedtls_cipher_info_t *cipher_info;

	cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
    if (!cipher_info) return -1;

	mbedtls_cipher_init(&(h->ctx));

	ret = mbedtls_cipher_setup(&(h->ctx), cipher_info);
    if (ret != 0) goto aes_init_cleanup;
	return ret;

aes_init_cleanup:
	aes_fini(handle);
	return ret;
}
int aes_set_key(void *handle, const unsigned char *key, size_t klen){
	aes_handle_t *h = (aes_handle_t *)handle;
	int ret = -1;

	if(klen != 32) goto aes_set_key_cleanup;


	ret = mbedtls_cipher_setkey(
        &(h->ctx),
        key,
        key_len * 8,
        MBEDTLS_ENCRYPT   // same for decrypt
    );
    if (ret != 0) goto aes_set_key_cleanup;
	return ret;

aes_set_key_cleanup:
	aes_fini(handle);
	return ret;
}
int aes_set_iv(void *handle, const unsigned char *iv, size_t ivlen){
	aes_handle_t *h = (aes_handle_t *)handle;
	int ret = -1;

	if(ivlen != 16) goto aes_set_iv_cleanup;

	ret = mbedtls_cipher_set_iv(
        &ctx,
        iv,
        16
    );
    if (ret != 0) goto aes_set_iv_cleanup;
	return ret;

aes_set_iv_cleanup:
	aes_fini(handle);
	return ret;
}
int aes_crypt(void *handle, const unsigned char *in, size_t ilen, unsigned char *out, size_t *olen){
	aes_handle_t *h = (aes_handle_t *)handle;
	int ret = -1;

	ret = mbedtls_cipher_reset(&(h->ctx));
    if (ret != 0) goto aes_crypt_cleanup;

    ret = mbedtls_cipher_update(
        &(h->ctx),
        in,
        ilen,
        out,
        olen
    );
	return ret;

aes_crypt_cleanup:
	aes_fini(handle);
	return ret;
}

void aes_secure_zeroize(void *data, size_t len){
	mbedtls_platform_zeroize(data, len);
}
