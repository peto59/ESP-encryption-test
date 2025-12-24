#include "crc_wrap.h"

int crc_wrap_calc(void *handle, const unsigned char *in, size_t ilen, uint16_t *out){
    *out = esp_rom_crc16_le(0, in, ilen);
    *out = ntohs(*out);
	return 0;
}

