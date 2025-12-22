#ifndef PROV_H

#define PROV_H

#include "types.h"
#include <string.h>


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
 *		BUFF_ERR:
 *			ouput buffer too short, NOT notified
 *		COMM_ERR:
 *			communication failed, but key is written to key buffer
 *		COMM_GEN_ERR:
 *		  	internal error, NOT notified
 *		COMM_CRC_ERR:
 *			CRC could not be validated, NOT notified
 *
 *	In case of negative return value, the other side was notified
 */
int prov(encryption_t *handle, const unsigned char *line, size_t line_len, unsigned char *key, size_t *key_len);

#endif
