#include "../git-compat-util.h"
#include "sha256_x64.h"
#include <byteswap.h>

void shani_SHA256_Init(shani_SHA256_CTX *ctx)
{
	ctx->total_len = 0;
	ctx->len = 0;
	ctx->h[0] = 0x6a09e667ul;
	ctx->h[1] = 0xbb67ae85ul;
	ctx->h[2] = 0x3c6ef372ul;
	ctx->h[3] = 0xa54ff53aul;
	ctx->h[4] = 0x510e527ful;
	ctx->h[5] = 0x9b05688cul;
	ctx->h[6] = 0x1f83d9abul;
	ctx->h[7] = 0x5be0cd19ul;
}

void sha256_update(uint32_t *digest, const void *data, uint32_t numBlocks);
void shani_SHA256_Update(shani_SHA256_CTX *c, const void *data, size_t len)
{
    while (len > 0)
    {
        if (c->len == 0 && len >= 64)
        {
            sha256_update(c->h, data, len/64);
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
            sha256_update(c->h, c->msgbuf, 1);
            c->len = 0;
        }
    }
}

void shani_SHA256_Final(unsigned char *digest, shani_SHA256_CTX *c)
{
    c->msgbuf[c->len] = 0x80;
    ++c->len;
    memset(c->msgbuf + c->len, 0, 64 - c->len);
    if (c->len > (64-8))
    {
        sha256_update(c->h, c->msgbuf, 1);
        memset(c->msgbuf, 0, 64);
        c->len = 0;
    }

    for (int ibyte = 0; ibyte < 8; ++ibyte)
       c->msgbuf[63-ibyte] = (uint8_t)((c->total_len * 8ULL) >> (ibyte*8));

    sha256_update(c->h, c->msgbuf, 1);
    c->len = 0;
    
    // flip endianness
    int i;
    for (i = 0; i < 32; i += 4) {
        *(uint32_t *)(digest + i) = __bswap_32(c->h[i / 4]);
    }
}