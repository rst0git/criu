#ifndef __CR_COMPRESSION_H__
#define __CR_COMPRESSION_H__

int compress_data(const char *input_data, size_t input_size, char *compressed_data);
int decompress_data(const char *compressed_data, int compressed_size, size_t original_size, char *decompressed_data);

#endif /* __CR_COMPRESSION_H__ */
