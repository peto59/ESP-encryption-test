idf_component_register(
	SRCS
		"esp-encryption-test.c"
	INCLUDE_DIRS "."
    PRIV_REQUIRES io_helpers
    PRIV_REQUIRES mbedtls_abstraction
    PRIV_REQUIRES encryption
    PRIV_REQUIRES tests
    REQUIRES espcoredump
)
