
#ifndef DH_H

#define DH_H

#include "types.h"
#include "enc.h"
#include <stdlib.h>
#include <time.h>

/*
 * ret: 
 *		OK: 
 *			the key in binary form was written to key buffer
 *		GEN_ERR:
 *		  	internal error, notified
 *		CRC_ERR:
 *			CRC could not be validated, notified
 *		INPUT_ERR:
 *			invalid content of line buffer, NOT notified
 *		COMM_ERR:
 *			communication failed, but key is written to key buffer
 *		COMM_GEN_ERR:
 *		  	internal error, NOT notified
 *		COMM_CRC_ERR:
 *			CRC could not be validated, NOT notified
 *		FINI_ERR:
 *			ECDH resource could not be finalized, considered as success
 *		COMM_FINI_ERR
 *			ECDH resource could not be finalized and other side could not be notified
 *
 *	In case of negative return value, the other side was notified
 */
int dhke(encryption_t *handle, const unsigned char *line, size_t line_len);

#endif
