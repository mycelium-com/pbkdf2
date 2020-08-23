#include "hmac_sha2.h"
#include "hmac_sha3.h"

#include <string.h>

static inline void
be32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void pbkdf2_sha256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_sha256_ctx PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha256_init(&PShctx, passwd, passwdlen);
    hmac_sha256_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha256_ctx));
        hmac_sha256_update(&hctx, ivec, 4);
        hmac_sha256_final(&hctx, U, SHA256_DIGEST_SIZE);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha256_init(&hctx, passwd, passwdlen);
            hmac_sha256_update(&hctx, U, 32);
            hmac_sha256_final(&hctx, U, SHA256_DIGEST_SIZE);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32) {
            clen = 32;
        }
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_sha256_ctx));
}

/**
 * PBKDF2_SHA3_256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA3-256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void pbkdf2_sha3_256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_sha3_256_ctx PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha3_256_init(&PShctx, passwd, passwdlen);
    hmac_sha3_256_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha256_ctx));
        hmac_sha3_256_update(&hctx, ivec, 4);
        hmac_sha3_256_final(&hctx, U, SHA256_DIGEST_SIZE);

        /* T_i = U_1 ... */
        memcpy(T, U, 32);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha3_256_init(&hctx, passwd, passwdlen);
            hmac_sha3_256_update(&hctx, U, 32);
            hmac_sha3_256_final(&hctx, U, SHA256_DIGEST_SIZE);

            /* ... xor U_j ... */
            for (k = 0; k < 32; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32) {
            clen = 32;
        }
        memcpy(&buf[i * 32], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_sha3_256_ctx));
}
