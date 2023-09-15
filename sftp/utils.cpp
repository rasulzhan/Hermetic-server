#include "utils.h"
#include <cstring>
#include <cstdlib>
#ifdef __linux__
#else
#include <Windows.h>
#endif

uint32_t ntonu32(uint32_t val)
{
    val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
    return (val << 16) | (val >> 16);
}

uint64_t ntonu64(uint64_t val)
{
    val = ((val << 8) & 0xFF00FF00FF00FF00ULL) | ((val >> 8) & 0x00FF00FF00FF00FFULL);
    val = ((val << 16) & 0xFFFF0000FFFF0000ULL) | ((val >> 16) & 0x0000FFFF0000FFFFULL);
    return (val << 32) | (val >> 32);
}

uint32_t ntonu32(const unsigned char *buf)
{
    return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

void htonu32(unsigned char *buf, uint32_t value)
{
    buf[0] = (value >> 24) & 0xFF;
    buf[1] = (value >> 16) & 0xFF;
    buf[2] = (value >> 8) & 0xFF;
    buf[3] = value & 0xFF;
}

size_t unicode_to_utf8(int unicode, unsigned char* out)
{
    size_t outlen = -1;
    if (unicode >= 0 && unicode <= 0x7f) { // 7F(16) = 127(10)
        out[0] = unicode;
        outlen = 1;
    } else if (unicode <= 0x7ff) { // 7FF(16) = 2047(10)
        unsigned char c1 = 192, c2 = 128;

        for (int k = 0; k < 11; ++k) {
            if (k < 6)  c2 |= (unicode % 64) & (1 << k);
            else c1 |= (unicode >> 6) & (1 << (k - 6));
        }
        out[0] = c1;
        out[1] = c2;
        outlen = 2;
    } else if (unicode <= 0xffff) { // FFFF(16) = 65535(10)
        unsigned char c1 = 224, c2 = 128, c3 = 128;

        for (int k = 0; k < 16; ++k) {
            if (k < 6)  c3 |= (unicode % 64) & (1 << k);
            else if (k < 12) c2 |= (unicode >> 6) & (1 << (k - 6));
            else c1 |= (unicode >> 12) & (1 << (k - 12));
        }
        out[0] = c1;
        out[1] = c2;
        out[2] = c3;
        outlen = 3;
    } else if (unicode <= 0x1fffff)  // 1FFFFF(16) = 2097151(10)
    {
        unsigned char c1 = 240, c2 = 128, c3 = 128, c4 = 128;

        for (int k = 0; k < 21; ++k) {
            if (k < 6)  c4 |= (unicode % 64) & (1 << k);
            else if (k < 12) c3 |= (unicode >> 6) & (1 << (k - 6));
            else if (k < 18) c2 |= (unicode >> 12) & (1 << (k - 12));
            else c1 |= (unicode >> 18) & (1 << (k - 18));
        }
        out[0] = c1;
        out[1] = c2;
        out[2] = c3;
        out[3] = c4;
        outlen = 4;
    }
    return outlen;
}

size_t unicode_to_utf8(const unsigned char* in, size_t in_len, unsigned char* out)
{
    wchar_t c[2];
    unsigned char code[4];
    unsigned char* p = out;
    for (size_t i = 0; i < in_len; i++) {
#ifdef __linux__
        // depends on the LC_CTYPE category of the selected C locale
        mbstowcs(c, (char*)(in + i), 1);
#else
        MultiByteToWideChar(CP_THREAD_ACP, 0, (char*)(in + i), 1, c, 2);
#endif
        size_t l = unicode_to_utf8((int)c[0], code);
        if (l > 0) {
            memcpy(p, code, l);
            p += l;
        }
    }
    return (size_t)p - (size_t)out;
}

static const short base64_reverse_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

int base64_decode(char** out, size_t& out_len, const char* src, size_t src_len)
{
    unsigned char *s, *d;
    short v;
    int i = 0, len = 0;

    *out = new char[(3 * src_len / 4) + 1];
    d = (unsigned char *)*out;
    for (s = (unsigned char *)src; ((char *)s) < (src + src_len); s++) {
        v = base64_reverse_table[*s];
        if (v < 0)
            continue;
        switch (i % 4) {
        case 0:
            d[len] = (unsigned char)(v << 2);
            break;
        case 1:
            d[len++] |= v >> 4;
            d[len] = (unsigned char)(v << 4);
            break;
        case 2:
            d[len++] |= v >> 2;
            d[len] = (unsigned char)(v << 6);
            break;
        case 3:
            d[len++] |= v;
            break;
        }
        i++;
    }
    if ((i % 4) == 1) {
        return -1;
    }

    out_len = len;
    return 1;
}

int readline(char *line, int line_size, FILE *fp)
{
    size_t len;
    if (!line) {
        return -1;
    }
    if (!fgets(line, line_size, fp)) {
        return -1;
    }
    if (*line) {
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
    }
    if (*line) {
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\r') {
            line[len - 1] = '\0';
        }
    }
    return 0;
}
