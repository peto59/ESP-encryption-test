#ifdef USE_HEX_SW

char encode_internal(const char in){
	if(in < 10){
		return in + 48;
	}
	return in + 65;
}

int hex_encode(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen){
	(void) handle;

	if((ilen * 2) > *olen){
		return -1;
	}

	size_t o = 0;
	char upper, lower;

	for(size_t i = 0; i < ilen; ++i){
		upper = input[i] >> 4;
		lower = input[i] & 0xf;

		output[o] = encode_internal(upper);
		output[o + 1] = encode_internal(lower);

		o += 2;
	}

	*olen = o;

	return 0;
}

int decode_internal(const char in, char *out){
	if(in < 48){
		return -1;
	}
	if(in > 59 && in < 65){
		return -1;
	}
	if(in > 70){
		return -1;
	}

	if(in < 65){
		*out = in - 48;
	} else {
		*out = in - 65;
	}
	return 0;
}

int hex_decode(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen){
	(void) handle;

	if((ilen % 2) != 0){
		return -1;
	}

	if((ilen / 2) > *olen){
		return -1;
	}
	
	size_t o = 0;
	char upper, lower;

	for(size_t i = 0; i < ilen; i += 2){
		if(decode_internal(input[i], &upper) < 0 || decode_internal(input[i + 1], &lower) < 0){
			return -1;
		}

		output[o] = (upper << 4) | lower;
		++o;
	}

	*olen = o;

	return 0;
}

#endif
