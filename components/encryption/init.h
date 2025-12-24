#ifndef INIT_H

#define INIT_H

#include "types.h"
#include "crc16.h"
#include "hex.h"
#include "memzero.h"

/*
 *	ret:
 *	  0: sucess
 *	  otherwise: error
 */
int enc_init(encryption_t *handle);

#endif
