#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha2.h"

#define UNPACK32(x, str)                      \
{                                             \
*((str) + 3) = (unsigned char) ((x)      );       \
*((str) + 2) = (unsigned char) ((x) >>  8);       \
*((str) + 1) = (unsigned char) ((x) >> 16);       \
*((str) + 0) = (unsigned char) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
*(x) =   ((unsigned int) *((str) + 3)      )    \
| ((unsigned int) *((str) + 2) <<  8)    \
| ((unsigned int) *((str) + 1) << 16)    \
| ((unsigned int) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
+ SHA256_F3(w[i - 15]) + w[i - 16]; \
}

unsigned int sha256_h0[8] =
{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

unsigned int sha256_k[64] =
{ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/* SHA-256 functions */

void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    unsigned int w[64];
    unsigned int wv[8];
    unsigned int t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int)block_nb; i++) {
        sub_block = message + (i << 6);

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
            + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len);
    sha256_final(&ctx, digest);
}

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    memcpy(&ctx->block[ctx->len], message, rem_len);

    if (ctx->len + len < SHA256_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA256_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha256_transf(ctx, ctx->block, 1);
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE;

    memcpy(ctx->block, &shifted_message[block_nb << 6],
           rem_len);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

    block_nb = (1 + ((SHA256_BLOCK_SIZE - 9)
                     < (ctx->len % SHA256_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 6;

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]);
    }
}

unsigned char * HMAC_SHA256(const char * msg, const char * key)
{
    unsigned int blocksize = 64;
    unsigned char * Key0 = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_ipad = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_ipad_concat_text = (unsigned char *)calloc( (blocksize + strlen(msg)), sizeof(unsigned char));
    unsigned char * Key0_ipad_concat_text_digest = (unsigned char *)calloc( blocksize, sizeof(unsigned char));
    unsigned char * Key0_opad = (unsigned char *)calloc(blocksize, sizeof(unsigned char));
    unsigned char * Key0_opad_concat_prev = (unsigned char *)calloc(blocksize + 32, sizeof(unsigned char));

    unsigned char * HMAC_SHA256 = (unsigned char *)malloc(32 * sizeof(unsigned char));

    if (strlen(key) < blocksize) {
        for (int i = 0; i < blocksize; i++) {
            if (i < strlen(key)) Key0[i] = key[i];
            else Key0[i] = 0x00;
        }
    }
    else if (strlen(key) > blocksize) {
        sha256(key, strlen(key), Key0);
        for (unsigned char i = strlen(key); i < blocksize; i++) {
            Key0[i] = 0x00;
        }
    }

    for (int i = 0; i < blocksize; i++) {
        Key0_ipad[i] = Key0[i] ^ 0x36;
    }
    for (int i = 0; i < blocksize; i++) {
        Key0_ipad_concat_text[i] = Key0_ipad[i];
    }
    for (int i = blocksize; i < blocksize + strlen(msg); i++) {
        Key0_ipad_concat_text[i] = msg[i - blocksize];
    }

    sha256(Key0_ipad_concat_text, blocksize + (unsigned int)strlen(msg), Key0_ipad_concat_text_digest);

    for (int i = 0; i < blocksize; i++) {
        Key0_opad[i] = Key0[i] ^ 0x5C;
    }

    for (int i = 0; i < blocksize; i++) {
        Key0_opad_concat_prev[i] = Key0_opad[i];
    }
    for (int i = blocksize; i < blocksize + 32; i++) {
        Key0_opad_concat_prev[i] = Key0_ipad_concat_text_digest[i - blocksize];
    }

    sha256(Key0_opad_concat_prev, blocksize + 32, HMAC_SHA256);
    return HMAC_SHA256;
}


int main()
{
    unsigned char * result;

    result = HMAC_SHA256("Sample #1", "MyKey");

    unsigned char arr[32] = { 0 };
    memcpy(arr, result, 32);

    for(int i = 0; i < 32; i++) {
        printf("%#02x, ", arr[i]);
    }
    return 0;
}
