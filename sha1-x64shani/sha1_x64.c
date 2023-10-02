#include "../git-compat-util.h"
#include "sha1_x64.h"
#include <byteswap.h>

// static inline void shani_SHA1_Init(shani_SHA_CTX *c);

void shani_SHA1_Init(shani_SHA_CTX *c)
{
    static const uint32_t sha1InitialDigest[5] = {
           0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    };
    memcpy(c->h, sha1InitialDigest, 20);
    c->len = 0;
    c->total_len = 0;
}

void sha1_update(void *c, const void *d, int l);
void shani_SHA1_Update(shani_SHA_CTX *c, const void *data, unsigned long len)
{
    while (len > 0)
    {
        if (c->len == 0 && len >= 64)
        {
            sha1_update(c->h, data, len/64);
            unsigned long bytes_hashed = (len/64)*64;
            data += bytes_hashed;
            len -= bytes_hashed;
            c->total_len += bytes_hashed;
            continue;
        }
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
        size_t cpy = MIN(64 - c->len, len);
#undef MIN
        memcpy(c->msgbuf + c->len, data, cpy);
        data += cpy;
        len -= cpy;
        c->len += cpy;
        c->total_len += cpy;

        if (c->len == 64)
        {
            sha1_update(c->h, c->msgbuf, 1);
            c->len = 0;
        }
    }
}

void shani_SHA1_Final(unsigned char *md, shani_SHA_CTX *c)
{
    c->msgbuf[c->len] = 0x80;
    ++c->len;
    memset(c->msgbuf + c->len, 0, 64 - c->len);
    if (c->len > (64-8))
    {
        sha1_update(c->h, c->msgbuf, 1);
        memset(c->msgbuf, 0, 64);
        c->len = 0;
    }

    for (int ibyte = 0; ibyte < 8; ++ibyte)
       c->msgbuf[63-ibyte] = (uint8_t)((c->total_len * 8ULL) >> (ibyte*8));

    sha1_update(c->h, c->msgbuf, 1);
    c->len = 0;    

    // flip endianness
    int i;
    for (i = 0; i < 20; i += 4) {
        *(uint32_t *)(md + i) = __bswap_32(c->h[i / 4]);
    }
}
