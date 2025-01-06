#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "common/xmalloc.h"

#include <lz4.h>
#include <lz4frame.h>


#include <stdint.h>
#include <stdlib.h>
#include <lz4.h>

int compress_data(const char *input_data, size_t input_size, char *compressed_data)
{
	int compressed_size, max_compressed_size;

	max_compressed_size = LZ4_compressBound(input_size);
	compressed_size = LZ4_compress_default(input_data, compressed_data, input_size, max_compressed_size);
	if (compressed_size <= 0)
		return -1;

	return compressed_size;
}


int decompress_data(const char *compressed_data, int compressed_size, size_t original_size, char *decompressed_data)
{
	if (LZ4_decompress_safe(compressed_data, decompressed_data, compressed_size, original_size) < 0)
		return -1;

	return 0;
}
