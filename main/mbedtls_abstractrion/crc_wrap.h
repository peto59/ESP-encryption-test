#pragma once

#include "esp_rom_crc.h"

int crc_wrap_calc(void *handle, const unsigned char *in, size_t ilen, uint16_t *out);
