#include "fini.h"

void fini(encryption_t *handle){
	handle->aes_handle.secure_zeroize(handle->aes_handle.provisioned_key, AES_KEY_SIZE);
	handle->aes_handle.secure_zeroize(handle->aes_handle.negotiated_key, AES_KEY_SIZE);
	//handle->aes_handle.secure_zeroize(&(handle->aes_handle.device_iv), sizeof(handle->aes_handle.device_iv));
	//handle->aes_handle.secure_zeroize(&(handle->aes_handle.my_iv), sizeof(handle->aes_handle.my_iv));
}
