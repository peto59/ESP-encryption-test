#include "hkdf.h"

int hkdf_transform(void *handle, const unsigned char *in, size_t ilen, unsigned char *out, size_t *olen){
	(void)handle;

	if(*olen < 32){
		return -1;
	}
	if(ilen != 32){
		return -1;
	}
	*olen = 32;

	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(
        MBEDTLS_MD_SHA256
    );

    if (md == NULL)
        return -1;

    // Optional but strongly recommended
    const unsigned char salt[] = "ecdh-p256-salt";

    // Context binding (protocol, direction, version, etc.)
    const unsigned char info[] = "aes-ctr key";

    return mbedtls_hkdf(
        md,
        salt,
        sizeof(salt) - 1,
        in,
        ilen,
        info,
        sizeof(info) - 1,
        out,
        *olen
    );
}
