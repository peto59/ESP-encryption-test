idf_component_register(
	SRCS
		"crc16.c"
		"dh.c"
		"enc.c"
		"fini.c"
		"helpers.c"
		"hex.c"
		"init.c"
		"memzero.c"
		"prov.c"
	INCLUDE_DIRS "."
)

# Define a macro for all files in this component
target_compile_definitions(${COMPONENT_LIB} PRIVATE USE_HEX_SW=1)
target_compile_definitions(${COMPONENT_LIB} PRIVATE DEBUG=1)
