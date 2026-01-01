#ifndef __UAV_UTILS_H
#define __UAV_UTILS_H

#include <sys/types.h>
#include <stdio.h>

#define SHA256_DIGEST_LEN 32

size_t safe_strcpy(char *dst, const char *src, size_t size);
ssize_t digest_to_hex(const unsigned char *digest, int len, char *buf);
ssize_t digest_from_hex(const char *buf, int len, unsigned char *digest);
int compare_digest(const unsigned char *a, const unsigned char *b, int len);
int zip_extract_directory(const char *src, const char *output_path);
int copyfile(const char *src, const char *dst);
int write_file(const char *path, const char *data, size_t len);
int write_file_str(const char *path, const char *str);
ssize_t read_file(const char *path, char *buf, size_t size);
int rmtree(const char *path);

#endif // !__UAV_UTILS_H
