/*
 * SHA1 routine using x64 SHA-NI instructions
 */

typedef struct shani_SHA_CTX
{
    uint32_t h[5];
    int len;
    uint64_t total_len;
    char msgbuf[64];
} shani_SHA_CTX;


void shani_SHA1_Init(shani_SHA_CTX *ctx);
void shani_SHA1_Update(shani_SHA_CTX *ctx, const void *dataIn, size_t len);
void shani_SHA1_Final(unsigned char hashout[20], shani_SHA_CTX *ctx);

#define platform_SHA_CTX	shani_SHA_CTX
#define platform_SHA1_Init	shani_SHA1_Init
#define platform_SHA1_Update	shani_SHA1_Update
#define platform_SHA1_Final	shani_SHA1_Final
