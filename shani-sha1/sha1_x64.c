/* this is only to get definitions for memcpy(), ntohl() and htonl() */
#include "../git-compat-util.h"
#include "sha1_x64.h"


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
    return 1;
}


/*
 * Encodes input (u_int32_t) into output (unsigned char). Assumes len is
 * a multiple of 4. This is not compatible with memcpy().
 */
void
Encode(unsigned char *output, u_int32_t *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j + 3] = input[i] & 0xff;
		output[j + 2] = (input[i] >> 8) & 0xff;
		output[j + 1] = (input[i] >> 16) & 0xff;
		output[j] = (input[i] >> 24) & 0xff;
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

    Encode(md, c->h, 20);
    return 1;
}
