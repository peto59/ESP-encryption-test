#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "esp_log.h"
#include "io_helpers.h"
#include "encryption.h"
#include "mbedtls_abstraction.h"
#include "tests.h"

int struct_init(encryption_t *handle){
	handle->aes_handle.handle = malloc(sizeof(aes_handle_t));
	if(handle->aes_handle.handle == NULL) return -1;

	handle->aes_handle.init = &aes_init;
	handle->aes_handle.set_key = &aes_set_key;
	handle->aes_handle.set_iv = &aes_set_iv;
	handle->aes_handle.crypt = &aes_crypt;
	handle->aes_handle.secure_zeroize = &aes_secure_zeroize;
	handle->aes_handle.fini = &aes_fini;

	handle->ecdh_handle.handle = malloc(sizeof(ecdh_handle_t));
	if(handle->ecdh_handle.handle == NULL) return -1;

	handle->ecdh_handle.init = &ecdh_init;
	handle->ecdh_handle.get_pubkey = &ecdh_get_pubkey;
	handle->ecdh_handle.import_pubkey = &ecdh_import_pubkey;
	handle->ecdh_handle.get_key = &ecdh_get_key;
	handle->ecdh_handle.fini = &ecdh_fini;

	handle->hkdf_handle.handle = NULL;
	handle->hkdf_handle.transform = &hkdf_transform;

	handle->comm_handle.handle = NULL;
	handle->comm_handle.write = &robust_write;

	handle->sha256_handle.handle = NULL;
	handle->sha256_handle.calc = &sha256_calc;

	handle->crc_handle.handle = NULL;
	handle->crc_handle.calc = &crc_wrap_calc;

	handle->hex_handle.handle = NULL;
	handle->hex_handle.encode = NULL;
	handle->hex_handle.decode = NULL;

	return 0;
}

void app_main(void) {

	encryption_t handle;
	char buf[512];
	char decrypted[512];
	size_t dec_len;
	int len;
    int ret;

    printf("Hello World!\n");

	if(struct_init(&handle) < 0){
		printf("struct init failed\n");
		return;
	}

	if(enc_init(&handle) != 0){
		printf("init failed\n");
		return;
	}

    if(hex_tests(&handle) != 0){
        printf("hex_tests failed");
        return;
    }

	#define PROV_LEN 64 + 4 + 1 + 8
	len = full_read(STDIN_FILENO, buf, PROV_LEN + 1);
	buf[PROV_LEN] = '\0';
	printf("You typed: %s\n", buf);

	size_t key_len = 32;
	unsigned char key[key_len];

	if((ret = prov(&handle, (unsigned char *)buf, PROV_LEN, key, &key_len)) != OK){
		printf("prov failed: %d\n", ret);
		return;
	}
	if(key_len != 32){
		printf("prov len failed\n");
		return;
	}

	#define DHKE_LEN 8 + 4 + 1 + 8 + 1 + 128
	len = full_read(STDIN_FILENO, buf, 64);
	//printf("You typed: %s\n", buf);
    len += full_read(STDIN_FILENO, buf + 64, DHKE_LEN - 64 + 1);
    /*for(int i = 0; i < DHKE_LEN; i++){
        printf("%c\n", buf[i]);
    }*/
    buf[len] = '\0';
	printf("You typed: %s\n", buf);

	if((ret = dhke(&handle, (unsigned char *)buf, DHKE_LEN)) != OK){
		printf("dhke failed: %d\n", ret);
		return;
	}

	const TickType_t xDelay = 500 / portTICK_PERIOD_MS;

	while(1){
		len = robust_read(STDIN_FILENO, buf, 511);
		buf[len] = '\0';
		if (len >= 0) {
			printf("You typed: %s\n", buf);
			if((ret = dec(&handle, (unsigned char *)buf, len, (unsigned char *)decrypted, &dec_len)) != OK){
				printf("dec failed: %d\n", ret);
			} else {
				decrypted[dec_len] = '\0';
				printf("dec: %s\n", decrypted);
			}
		}
		vTaskDelay( xDelay );
	}
}
