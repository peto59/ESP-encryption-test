#include "prov.h"


// TODO: refactor

int prov_internal(encryption_t *handle, const unsigned char *data, unsigned char *key, size_t *key_len);

int prov
	(
		encryption_t *handle,
		const unsigned char *line,
		size_t line_len,
		unsigned char *key,
		size_t *key_len
	)	
{

	char shift = 0;

	if(line_len < 69){
		return INPUT_ERR;
	}

	if(memcmp("AT", line, 2) == 0){
		if(memcmp("+PROV=", line + 2, 6) == 0){
			shift = 1;
			line_len -= 8;
		} else {
			return INPUT_ERR;
		}
	}

	const unsigned char *data = shift == 0 ? line : line + 8;

	if(data[CRC_HEX_LEN] != ','){
		return INPUT_ERR;
	}

	int ret = prov_internal(handle, data, key, key_len);

	if(ret == OK){
		if(handle->comm_handle.write(handle->comm_handle.handle, "+PROV:OK\n", 9) < 0){
			return COMM_ERR;
		}
		return OK;

	} else {
		if(handle->comm_handle.write(handle->comm_handle.handle, "+PROV:ERROR\n", 12) < 0){
			return ret * -1;
		}
		return ret;
	}

	return OK;
}

int prov_internal(encryption_t *handle, const unsigned char *data, unsigned char *key, size_t *key_len){

	size_t crc_buf_len = CRC_BUF_LEN,
		   aes_len = AES_KEY_SIZE;

	const unsigned char *crc_hex = data,
						*aes_hex = data + CRC_HEX_LEN + 1;

	unsigned char crc_buf[CRC_BUF_LEN],
				  aes[AES_KEY_SIZE];

	uint16_t crc;

	if(handle->hex_handle.decode(handle->hex_handle.handle, crc_hex, CRC_HEX_LEN, crc_buf, &crc_buf_len) < 0){
		return GEN_ERR;
	}

	if(handle->hex_handle.decode(handle->hex_handle.handle, aes_hex, AES_HEX_LEN, aes, &aes_len) < 0){
		return GEN_ERR;
	}

	if(handle->crc_handle.calc(handle->crc_handle.handle, aes, aes_len, &crc) < 0){
		handle->aes_handle.secure_zeroize(aes, AES_KEY_SIZE);
		return GEN_ERR;
	}

	if(sizeof(crc) != crc_buf_len){
		handle->aes_handle.secure_zeroize(aes, AES_KEY_SIZE);
		return CRC_ERR;
	}
	if(memcmp(crc_buf, &crc, sizeof(crc)) != 0){
		handle->aes_handle.secure_zeroize(aes, AES_KEY_SIZE);
		return CRC_ERR;
	}

	if(aes_len > *key_len){
		handle->aes_handle.secure_zeroize(aes, AES_KEY_SIZE);
		return BUFF_ERR;
	}

	*key_len = aes_len;
	memcpy(key, aes, aes_len);
	memcpy(handle->aes_handle.provisioned_key, aes, aes_len);
	handle->aes_handle.secure_zeroize(aes, AES_KEY_SIZE);
	return OK;
}
