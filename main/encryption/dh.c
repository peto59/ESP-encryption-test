#include "dh.h"

// TODO: refactor

int dhke(encryption_t *handle, const unsigned char *line, size_t line_len){
	char shift = 0;
	unsigned char response[6 + PARTIAL_IV_HEX_LEN + 1 + DH_KEY_HEX_LEN + 1 + SIGNATURE_HEX_LEN + 1] = {'+', 'D', 'H', 'K', 'E', ':'};
	response[6 + PARTIAL_IV_HEX_LEN] = response[6 + PARTIAL_IV_HEX_LEN + 1 + DH_KEY_HEX_LEN] = ',';
	response[6 + PARTIAL_IV_HEX_LEN + 1 + DH_KEY_HEX_LEN + 1 + SIGNATURE_HEX_LEN] = '\n';
	unsigned char *partial_iv = response + 6;
	unsigned char *puk = partial_iv + PARTIAL_IV_HEX_LEN + 1;
	unsigned char *sig = puk + DH_KEY_HEX_LEN + 1;

	if(line_len < 142){
		return INPUT_ERR;
	}

	if(memcmp("AT", line, 2) == 0){
		if(memcmp("+DHKE=", line + 2, 6) == 0){
			shift = 1;
			line_len -= 8;
		} else {
			return INPUT_ERR;
		}
	}

	const unsigned char *data = shift == 0 ? line : line + 8;

	if(data[CRC_HEX_LEN] != ',' || data[CRC_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN]){
		return INPUT_ERR;
	}

	int ret = dhke_internal(handle, data, partial_iv, puk, sig);

	if(ret == OK || ret == FINI_ERR){
		if(handle->comm_handle.write(handle->comm_handle.handle, response, 9) < 0){
			return ret == OK ? COMM_ERR : COM_FINI_ERR;
		}
		return ret;

	} else {
		if(handle->comm_handle.write(handle->comm_handle.handle, "+DHKE:ERROR\n", 12) < 0){
			return ret * -1;
		}
		return ret;
	}

	return OK;
}

int dhke_internal(encryption_t *handle, const unsigned char *data, unsigned char *partial_iv, unsigned char *puk, unsigned char *sig_hex){

	size_t crc_buf_len = CRC_BUF_LEN,
		   iv_len = PARTIAL_IV_BUF_LEN,
		   dh_len = DH_KEY_LEN,
		   my_dh_key_len = DH_KEY_LEN,
		   shared_secret_len = AES_KEY_LEN,
		   aes_len = AES_KEY_LEN,
		   sig_len = SIGNATURE_LEN,
		   sig_enc_len = SIGNATURE_LEN;
		   puk_len = DH_KEY_HEX_LEN;
		   parial_iv = PARTIAL_IV_HEX_LEN;
		   sig_hex_len = SIGNATURE_HEX_LEN;

	// TODO: USELESS PARSE LINE DIRECTLY!
	unsigned char crc_hex[CRC_HEX_LEN],
				  crc_buf[CRC_BUF_LEN],
				  iv_hex[PARTIAL_IV_HEX_LEN],
				  iv_buf[PARTIAL_IV_BUF_LEN],
				  dh_hex[DH_KEY_HEX_LEN],
				  dh_key[DH_KEY_LEN + 1] = {0x04},
				  my_dh[DH_KEY_LEN],
				  shared_secret[AES_KEY_LEN],
				  aes[AES_KEY_LEN],
				  sig[SIGNATURE_LEN],
				  sig_enc[SIGNATURE_LEN];


	uint16_t crc;
	uint32_t iv;
	int ret;
	handle->aes_handle->use_neg_key = 0;
	handle->aes_handle->key_enrolled = 0;

	memcpy(crc_hex, data, CRC_HEX_LEN);
	memcpy(iv_hex, data + CRC_HEX_LEN + 1, PARTIAL_IV_HEX_LEN);
	memcpy(dh_hex, data + CRC_HEX_LEN + 1 + PARTIAL_IV_HEX + 1, DH_KEY_HEX_LEN);

	if(handle->hex_handle.decode(handle->hex_handle.handle, crc_hex, CRC_HEX_LEN, crc_buf, &crc_buf_len) < 0){
		return GEN_ERR;
	}

	if(handle->hex_handle.decode(handle->hex_handle.handle, iv_hex, PARTIAL_IV_HEX_LEN, iv_buf, &iv_len) < 0){
		return GEN_ERR;
	}
	if(sizeof(handle->aes_handle.device_iv) != iv_len){
		return GEN_ERR;
	}
	memcpy(&(handle->aes_handle.device_iv), iv_buf, iv_len);

	if(handle->hex_handle.decode(handle->hex_handle.handle, dh_hex, AES_HEX_LEN, dh_key + 1, &dh_len) < 0){
		return GEN_ERR;
	}
	++dh_len; // static 0x04 byte

	if(handle->crc_handle.calc(handle->crc_handle.handle, dh_key, dh_key_len, &crc) < 0){
		return GEN_ERR;
	}

	if(sizeof(crc) != crc_buf_len){
		return CRC_ERR;
	}
	if(memcmp(crc_buf, &crc, sizeof(crc)) != 0){
		return CRC_ERR;
	}

	if(handle->ecdh_handle.init != NULL && handle->ecdh_handle.init(handle->ecdh_handle.handle) < 0){
		return GEN_ERR;
	}

	if(handle->ecdh_handle.get_pubkey(handle->ecdh_handle.handle, my_dh, &my_dh_len) < 0){
		return GEN_ERR;
	}
	if(my_dh_len != DH_KEY_LEN){
		return GEN_ERR;
	}
	--my_dh_len; //static 0x04 byte

	if(handle->ecdh_handle.import_pubkey(handle->ecdh_handle.handle, dh_key, dh_len) < 0){
		return GEN_ERR;
	}

	if(handle->ecdh_handle.get_key(handle->ecdh_handle.handle, shared_secret, &shared_secret_len) < 0){
		return GEN_ERR;
	}

	if(handle->hdfk_handle.transform(handle->hkdf_handle.handle, shared_secret, shared_secret_len, aes, &aes_len)){
		handle->aes_handle.secure_zeroize(shared_secret, AES_KEY_LEN);
		return GEN_ERR;
	}
	handle->aes_handle.secure_zeroize(shared_secret, AES_KEY_LEN);
	if(AES_KEY_LEN != aes_len){
		handle->aes_handle.secure_zeroize(aes, AES_KEY_LEN);
		return GEN_ERR;
	}

	memcpy(handle->aes_handle.negotiated_key, aes, AES_KEY_LEN);
	handle->aes_handle.secure_zeroize(aes, AES_KEY_LEN);

	srand(time(NULL));
	handle->aes_handle.my_iv = rand();
	
	if(handle->sha256_handle.calc(handle->sha256_handle.handle, my_dh + 1, my_dh_len, sig, &sig_len) < 0){
		return GEN_ERR;
	}

	if((ret = aes_op(handle, sig, sig_len, sig_enc, &sig_enc_len, 0)) != OK){
		return ret;
	}
	if(sig_enc_len != SIGNATURE_LEN){
		return GEN_ERR;
	}

	if(handle->hex_handle.encode(handle->hex_handle.handle,
								(unsigned char)(&(handle->aes_handle.my_iv)),
								sizeof(handle->aes_handle.my_iv),
								partial_iv, &partial_iv_len) < 0){
		return GEN_ERR;
	}
	if(partial_iv_len != PARTIAL_IV_HEX_LEN){
		return GEN_ERR;
	}
	if(handle->hex_handle.encode(handle->hex_handle.handle, my_dh + 1, my_dh_len, puk, &puk_len) < 0){
		return GEN_ERR;
	}
	if(puk_len != DH_KEY_HEX_LEN){
		return GEN_ERR;
	}
	if(handle->hex_handle.encode(handle->hex_handle.handle, sig_enc, sig_enc_len, sig_hex, &sig_hex_len) < 0){
		return GEN_ERR;
	}
	if(sig_hex_len != SIGNATURE_HEX_LEN){
		return GEN_ERR;
	}

	handle->aes_handle->use_neg_key = 1;
	handle->aes_handle->key_enrolled = 0;

	if(handle->ecdh_handle.fini != NULL && handle->ecdh_handle.fini(handle->ecdh_handle.handle) < 0){
		return FINI_ERR;
	}

	return OK;
}
