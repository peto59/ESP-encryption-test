#ifndef ENCRYPTION_TYPES_H

#define ENCRYPTION_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define AES_HEX_LEN 64
#define AES_KEY_SIZE 32

#define CRC_HEX_LEN 4
#define CRC_BUF_LEN 2

#define PARTIAL_IV_HEX_LEN 8
#define PARTIAL_IV_BUF_LEN 4

#define IV_BUF_LEN 16

#define DH_KEY_HEX_LEN 128
#define DH_KEY_LEN 64

#define SIGNATURE_HEX_LEN 64
#define SIGNATURE_LEN 32

// TODO: maybe change larger then 8bit types to arrays

struct AES_256_CTR_handle{
	void *handle;
	int (*init)(void *); //may be null
	int (*set_key)(void *, const unsigned char *, size_t); // buffer is 32 bytes long
	int (*set_iv)(void *, const unsigned char *, size_t); // buffer is 16 bytes long
	int (*crypt)(void *, const unsigned char *, size_t, unsigned char *, size_t *);
	void (*secure_zeroize)(void *, size_t); // may be null, if null SW implementation is used
	int (*fini)(void *); //may be null

	volatile uint32_t device_iv;
	volatile uint32_t my_iv;

	volatile unsigned char provisioned_key[AES_KEY_SIZE];
	volatile unsigned char negotiated_key[AES_KEY_SIZE];
	char use_neg_key;
	char key_enrolled;
};

struct ECDH_P256_handle{
	void *handle;
	int (*init)(void *); // may be null
	int (*get_pubkey)(void *, unsigned char *, size_t *); // buffer is 65 bytes long, expected is X9.63 uncompressed format
	int (*import_pubkey)(void *, const unsigned char *, size_t); // buffer is 65 bytes of X9.63 uncompressed format
	int (*get_key)(void *, unsigned char *, size_t *); // buffer is 32 bytes long key, which is fed to KDF
	int (*fini)(void *); // may be null
};

struct HKDF_handle{
	void *handle;
	int (*transform)(void *, const unsigned char *, size_t, unsigned char *, size_t *); // both buffers are 32 bytes long
};

struct comm_handle{
	void *handle;
	ssize_t (*write)(void *, const char *, size_t);
};

struct SHA256_handle{
	void *handle;
	int (*calc)(void *, const unsigned char *, size_t, unsigned char *, size_t *);
};

struct CRC16_handle{
	void *handle;
	int (*calc)(void *, const unsigned char *, size_t, uint16_t *); // may be null, if null SW implementation is used
};

struct HEX_handle{
	void *handle;
	int (*encode)(void *, const unsigned char *, size_t, unsigned char *, size_t *); // may be null, if null SW implementation is used
	int (*decode)(void *, const unsigned char *, size_t, unsigned char *, size_t *); // may be null, if null SW implementation is used
};

typedef struct AES_256_CTR_handle AES_256_CTR_handle_t;
typedef struct ECDH_P256_handle ECDH_P256_handle_t;
typedef struct HKDF_handle HKDF_handle_t;
typedef struct comm_handle comm_handle_t;
typedef struct SHA256_handle SHA256_handle_t;
typedef struct CRC16_handle CRC16_handle_t;
typedef struct HEX_handle HEX_handle_t;

struct encryption{
	AES_256_CTR_handle_t aes_handle;
	ECDH_P256_handle_t ecdh_handle;
	HKDF_handle_t hkdf_handle;
	comm_handle_t comm_handle;
	SHA256_handle_t sha256_handle;
	CRC16_handle_t crc_handle;
	HEX_handle_t hex_handle;
};

typedef struct encryption encryption_t;

enum {
	OK = 0,

	INPUT_ERR = 1,
	COMM_ERR = 2,
	BUFF_ERR = 100,

	GEN_ERR = -3,
	COMM_GEN_ERR = 3,

	CRC_ERR = -4,
	COMM_CRC_ERR = 4,

	FINI_ERR = -5,
	COMM_FINI_ERR = 5,

	IV_ERR = 6,
};

#endif
