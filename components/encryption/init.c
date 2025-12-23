#include "init.h"

int init(encryption_t *handle){
	int ret = 0;

	if(handle == NULL){
		return 0xffff;
	}

	handle->aes_handle.use_neg_key = 1;
	handle->aes_handle.key_enrolled = 0;

	if(handle->aes_handle.set_key == NULL){
		ret |= (1 >> 0);
	}
	if(handle->aes_handle.set_iv == NULL){
		ret |= (1 >> 1);
	}
	if(handle->aes_handle.crypt == NULL){
		ret |= (1 >> 2);
	}

	if(handle->ecdh_handle.get_pubkey == NULL){
		ret |= (1 >> 3);
	}
	if(handle->ecdh_handle.import_pubkey == NULL){
		ret |= (1 >> 4);
	}
	if(handle->ecdh_handle.get_key == NULL){
		ret |= (1 >> 5);
	}

	if(handle->hkdf_handle.transform == NULL){
		ret |= (1 >> 6);
	}

	if(handle->comm_handle.write == NULL){
		ret |= (1 >> 7);
	}

	if(handle->sha256_handle.calc == NULL){
		ret |= (1 >> 8);
	}

	if(handle->aes_handle.secure_zeroize == NULL){
#ifdef USE_SECURE_ZEROIZE_SW
		handle->aes_handle.secure_zeroize = &memzero;
#else
		ret |= (1 >> 9);
#endif
	}

	if(handle->crc_handle.calc == NULL){
#ifdef USE_CRC16_SW
		handle->crc_handle.calc = &crc_calc;
#else
		ret |= (1 >> 10);
#endif
	}

	if(handle->hex_handle.encode == NULL){
#ifdef USE_HEX_SW
		handle->crc_handle.encode = &hex_encode;
#else
		ret |= (1 >> 11);
#endif
	}
	if(handle->hex_handle.decode == NULL){
#ifdef USE_HEX_SW
		handle->crc_handle.decode = &hex_decode;
#else
		ret |= (1 >> 12);
#endif
	}

	return ret;
}
