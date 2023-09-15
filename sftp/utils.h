#ifndef __SSH_UTILS_H__
#define __SSH_UTILS_H__

#include <stdint.h>
#include <stdio.h>

uint32_t ntonu32(uint32_t val);
uint32_t ntonu32(const unsigned char *buf);
uint64_t ntonu64(uint64_t val);

void htonu32(unsigned char *buf, uint32_t value);

size_t unicode_to_utf8(int unicode, unsigned char* out);
size_t unicode_to_utf8(const unsigned char* in, size_t in_len, unsigned char* out);

int base64_decode(char** out, size_t& out_len, const char* src, size_t src_len);

int readline(char *line, int line_size, FILE *fp);

template<typename T>
void explicit_zero(T **p, size_t len)
{
    if (p && *p) {
        memset(*p, 0, len);
        delete[] *p;
        *p = NULL;
    }
}

#endif // __SSH_UTILS_H__