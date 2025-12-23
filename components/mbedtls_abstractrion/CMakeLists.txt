idf_component_register(
	SRCS
		"aes.c"
		"crc_wrap.c"
		"ecdh.c"
		"hkdf.c"
		"sha256.c"
	INCLUDE_DIRS "."
	REQUIRES mbedtls
)

