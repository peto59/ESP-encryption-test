#include "ecdh.h"

int ecdh_fini(void *handle){
	ecdh_handle_t *h = (ecdh_handle_t *)handle;
    mbedtls_ecdh_free(&(h->ctx));
    mbedtls_ctr_drbg_free(&(h->ctr_drbg));
    mbedtls_entropy_free(&(h->entropy));
	return 0;
}

int ecdh_init(void *handle){
	ecdh_handle_t *h = (ecdh_handle_t *)handle;
	const char *pers = "ecdh";
	int ret;

	mbedtls_ecdh_init(&(h->ctx));
	mbedtls_entropy_init(&(h->entropy));
	mbedtls_ctr_drbg_init(&(h->ctr_drbg));

    // RNG
    ret = mbedtls_ctr_drbg_seed(
        &(h->ctr_drbg),
        mbedtls_entropy_func,
        &(h->entropy),
        (const unsigned char *) pers,
        strlen(pers)
    );
    if (ret != 0) goto ecdh_init_cleanup;

    // Load P-256 curve
    ret = mbedtls_ecdh_setup(&ctx, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto ecdh_init_cleanup;

	return ret;

ecdh_init_cleanup:
	ecdh_fini(handle);
    return ret;
}

int ecdh_get_pubkey(void *handle, unsigned char *out, size_t *olen){
	ecdh_handle_t *h = (ecdh_handle_t *)handle;
	int ret;

    // Generate our keypair
    ret = mbedtls_ecdh_gen_public(
        &(h->ctx.grp),
        &(h->ctx.d),     // private key
        &(h->ctx.Q),     // public key
        mbedtls_ctr_drbg_random,
        &(h->ctr_drbg)
    );
    if (ret != 0) goto ecdh_get_pubkey_cleanup;

	ret = mbedtls_ecp_point_write_binary(
        &(h->ctx.grp),
        &(h->ctx.Q),
        MBEDTLS_ECP_PF_UNCOMPRESSED,
        olen,
        out,
        *olen
    );
    if (ret != 0) goto ecdh_get_pubkey_cleanup;

	return ret;

ecdh_get_pubkey_cleanup:
	ecdh_fini(handle);
    return ret;
}

int ecdh_import_pubkey(void *handle, const unsigned char *in, size_t ilen){
	ecdh_handle_t *h = (ecdh_handle_t *)handle;
	int ret;

    // Read peer public key (uncompressed form: 0x04 || X || Y)
    ret = mbedtls_ecp_point_read_binary(
        &(h->ctx.grp),
        &(h->ctx.Qp),
        in,
        ilen
    );
    if (ret != 0) goto ecdh_import_pubkey_cleanup;
	return ret;

ecdh_import_pubkey_cleanup:
	ecdh_fini(handle);
    return ret;
}

int ecdh_get_key(void *handle, unsigned char *out, size_t *olen){
	ecdh_handle_t *h = (ecdh_handle_t *)handle;
    int ret;

    // Compute shared secret
    ret = mbedtls_ecdh_compute_shared(
        &(h->ctx.grp),
		&(h->ctx.z),
        &(h->ctx.Qp),
        &(h->ctx.d),
        mbedtls_ctr_drbg_random,
        &(h->ctr_drbg)
    );
    if (ret != 0) goto ecdh_get_key_cleanup;

    // Export shared secret
    ret = mbedtls_mpi_write_binary(
        &(h->ctx.z),
        out,
        *olen
    );
    if (ret != 0) goto ecdh_get_key_cleanup;

    *olen = mbedtls_mpi_size(&(h->ctx.z));
	return ret;

ecdh_get_key_cleanup:
	ecdh_fini(handle);
    return ret;
}

