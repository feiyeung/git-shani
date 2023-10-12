/*
 * SHA256 routine using x64 SHA-NI instructions
 */

#define SHANI_SHA256_BLKSIZE 64

struct shani_SHA256_CTX {
    uint32_t h[8];
    int len;
    uint64_t total_len;
    char msgbuf[SHANI_SHA256_BLKSIZE];
};

typedef struct shani_SHA256_CTX shani_SHA256_CTX;

void shani_SHA256_Init(shani_SHA256_CTX *ctx);
void shani_SHA256_Update(shani_SHA256_CTX *c, const void *data, size_t len);
void shani_SHA256_Final(unsigned char *digest, shani_SHA256_CTX *c);

#define platform_SHA256_CTX	    shani_SHA256_CTX
#define platform_SHA256_Init	shani_SHA256_Init
#define platform_SHA256_Update	shani_SHA256_Update
#define platform_SHA256_Final	shani_SHA256_Final