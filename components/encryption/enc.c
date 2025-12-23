#include "enc.h"

int aes_op(encryption_t *handle, const unsigned char *data, size_t data_len, unsigned char *output, size_t *output_len, char increment){

	unsigned char full_iv_buf[IV_BUF_LEN];

	if(*output_len < data_len){
		return BUFF_ERR;
	}
	
	if(handle->aes_handle.key_enrolled == 0){
		if(handle->aes_handle.use_neg_key == 0){
			if(handle->aes_handle.set_key(handle->aes_handle.handle, handle->aes_handle.negotiated_key, AES_KEY_SIZE) < 0){
				return GEN_ERR;
			}
		} else {
			if(handle->aes_handle.set_key(handle->aes_handle.handle, handle->aes_handle.negotiated_key, AES_KEY_SIZE) < 0){
				return GEN_ERR;
			}
		}
		handle->aes_handle.key_enrolled = 1;
	}

	if(increment == 1) handle->aes_handle.my_iv += 1;
	memcpy(full_iv_buf, &(handle->aes_handle.my_iv), PARTIAL_IV_BUF_LEN);
	memcpy(full_iv_buf + 4, &(handle->aes_handle.device_iv), PARTIAL_IV_BUF_LEN);
	memcpy(full_iv_buf + 8, &(handle->aes_handle.my_iv), PARTIAL_IV_BUF_LEN);
	memcpy(full_iv_buf + 12, &(handle->aes_handle.device_iv), PARTIAL_IV_BUF_LEN);

	if(handle->aes_handle.set_iv(handle->aes_handle.handle, full_iv_buf, IV_BUF_LEN) < 0){
		return GEN_ERR;
	}

	if(handle->aes_handle.crypt(handle->aes_handle.handle, data, data_len, output, output_len) < 0){
		return GEN_ERR;
	}
	return OK;
}

int dec(encryption_t *handle, const unsigned char *line, size_t line_len, unsigned char *output, size_t *output_len){
	char shift = 0;

	size_t				device_partial_iv_len = PARTIAL_IV_BUF_LEN,
						modem_partial_iv_len = PARTIAL_IV_BUF_LEN,
						crc_buf_len = CRC_BUF_LEN,
						enc_data_buf_len;

	unsigned char		crc_buf[CRC_BUF_LEN],
						*enc_data_buf;

	const unsigned char	*device_partial_iv_hex = line,
						*modem_partial_iv_hex = line + PARTIAL_IV_HEX_LEN + 1,
						*crc_hex = line + PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1,
						*enc_data_hex = line + PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1 + CRC_HEX_LEN + 1 + sizeof(unsigned int) + 1;

	uint32_t device_partial_iv, modem_partial_iv;
	uint32_t my_iv_orig = handle->aes_handle.my_iv, device_iv_orig = handle->aes_handle.device_iv;
_Static_assert(sizeof(device_partial_iv) == PARTIAL_IV_BUF_LEN, "Platform data types len ERR");
	uint16_t crc;
_Static_assert(sizeof(crc) == CRC_BUF_LEN, "Platform data types len ERR");
	unsigned int enc_data_hex_len;
	int ret;

	if(memcmp("AT", line, 2) == 0){
		if(memcmp("+ENC=", line + 2, 5) == 0){
			shift = 1;
			line_len -= 7;
		} else {
			return INPUT_ERR;
		}
	}

	const unsigned char *data = shift == 0 ? line : line + 7;

	if(data[PARTIAL_IV_HEX_LEN] != ',' || data[PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN] != ','){
		return INPUT_ERR;
	}
	if(data[PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1 + CRC_HEX_LEN] != ','){
		return INPUT_ERR;
	}
	if(data[PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1 + CRC_HEX_LEN + 1 + sizeof(enc_data_hex_len)] != ','){
		return INPUT_ERR;
	}

	/*memcpy(device_partial_iv_hex, data, PARTIAL_IV_HEX_LEN);
	memcpy(modem_partial_iv_hex, data + PARTIAL_IV_HEX_LEN + 1, PARTIAL_IV_HEX_LEN);
	memcpy(crc_hex, data + PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1, CRC_HEX_LEN);*/
	memcpy(&enc_data_hex_len, data + PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1, sizeof(enc_data_hex_len));
	enc_data_hex_len = ntohl(enc_data_hex_len);

	if(line_len < PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1 + CRC_HEX_LEN + 1 + sizeof(enc_data_hex_len) + 1 + enc_data_hex_len){
		return INPUT_ERR;
	}

	if(handle->hex_handle.decode(handle->hex_handle.handle, crc_hex, CRC_HEX_LEN, crc_buf, &crc_buf_len) < 0){
		return GEN_ERR;
	}
	if(crc_buf_len != CRC_BUF_LEN){
		return GEN_ERR;
	}

	if(handle->hex_handle.decode(handle->hex_handle.handle, device_partial_iv_hex, PARTIAL_IV_HEX_LEN, (unsigned char *)(&device_partial_iv), &device_partial_iv_len) < 0){
		return GEN_ERR;
	}
	if(device_partial_iv_len != PARTIAL_IV_BUF_LEN){
		return GEN_ERR;
	}

	if(handle->hex_handle.decode(handle->hex_handle.handle, modem_partial_iv_hex, PARTIAL_IV_HEX_LEN, (unsigned char *)(&modem_partial_iv), &modem_partial_iv_len) < 0){
		return GEN_ERR;
	}
	if(modem_partial_iv_len != PARTIAL_IV_BUF_LEN){
		return GEN_ERR;
	}

	enc_data_buf_len = enc_data_hex_len / 2;
	enc_data_buf = malloc(enc_data_buf_len);
	if(enc_data_buf == NULL){
		return GEN_ERR;
	}
	if(handle->hex_handle.decode(handle->hex_handle.handle, enc_data_hex, enc_data_hex_len, enc_data_buf, &enc_data_buf_len) < 0){
		return GEN_ERR;
	}

	if(device_partial_iv <= handle->aes_handle.device_iv){
		return IV_ERR;
	}
	if(modem_partial_iv != handle->aes_handle.my_iv && modem_partial_iv + 1 != handle->aes_handle.my_iv){
		return IV_ERR;
	}
	if(modem_partial_iv >= (modem_partial_iv + 1)){
		return IV_ERR;
	}

	if(handle->crc_handle.calc(handle->crc_handle.handle, enc_data_buf, enc_data_buf_len, &crc) < 0){
		return GEN_ERR;
	}

	if(sizeof(crc) != crc_buf_len){
		return CRC_ERR;
	}
	if(memcmp(crc_buf, &crc, sizeof(crc)) != 0){
		return CRC_ERR;
	}

	handle->aes_handle.my_iv = modem_partial_iv;
	handle->aes_handle.device_iv = device_partial_iv;

	if((ret = aes_op(handle, enc_data_buf, enc_data_buf_len, output, output_len, 1)) != OK){
		//restore IVs if failed, otherwise entire communication will fail
		handle->aes_handle.my_iv = my_iv_orig;
		handle->aes_handle.device_iv = device_iv_orig;
		return ret;
	}

	return OK;

	//TODO: notes:
	//	equal to or lower by one + restoratian of newly received data == modem never increments IV
	//	there is no error response in +ENC
	//	switching around IV order is needlesly confusing (are there any crypto benefits?)
	//	<encrypted data lengh> being unsigned integer is equivalent to saying it can be 1 PB of data, for time being assuming uint32_t
	//	also endianity is unspecified, assuming network order
	//	also no hex format this time?
}

int enc_buf(encryption_t *handle, const unsigned char *line, size_t line_len, unsigned char *output, size_t *output_len){
	*output_len = line_len;
	memset(output, 0, *output_len);
	return 0;
}

int enc(encryption_t *handle, const unsigned char *line, size_t line_len){
	size_t output_len = 5 + PARTIAL_IV_HEX_LEN + 1 + PARTIAL_IV_HEX_LEN + 1 + CRC_HEX_LEN + 1 + sizeof(unsigned int) + (line_len * 2);
	unsigned char encrypted[output_len];

	int ret = enc_buf(handle, line, line_len, encrypted, &line_len);
	if(ret != OK){
		return ret;
	}

	if(handle->comm_handle.write(handle->comm_handle.handle, (char *)encrypted, line_len) < 0){
		return COMM_ERR;
	}
	return OK;
}

