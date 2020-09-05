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
    uint8_t U[SHA256_DIGEST_SIZE];
    uint8_t T[SHA256_DIGEST_SIZE];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha256_init(&PShctx, passwd, passwdlen);
    hmac_sha256_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * SHA256_DIGEST_SIZE < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha256_ctx));
        hmac_sha256_update(&hctx, ivec, 4);
        hmac_sha256_final(&hctx, U, SHA256_DIGEST_SIZE);

        /* T_i = U_1 ... */
        memcpy(T, U, SHA256_DIGEST_SIZE);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha256_init(&hctx, passwd, passwdlen);
            hmac_sha256_update(&hctx, U, SHA256_DIGEST_SIZE);
            hmac_sha256_final(&hctx, U, SHA256_DIGEST_SIZE);

            /* ... xor U_j ... */
            for (k = 0; k < SHA256_DIGEST_SIZE; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * SHA256_DIGEST_SIZE;
        if (clen > SHA256_DIGEST_SIZE) {
            clen = SHA256_DIGEST_SIZE;
        }
        memcpy(&buf[i * SHA256_DIGEST_SIZE], T, clen);
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
    uint8_t U[SHA3_256_DIGEST_LENGTH];
    uint8_t T[SHA3_256_DIGEST_LENGTH];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha3_256_init(&PShctx, passwd, passwdlen);
    hmac_sha3_256_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * SHA3_256_DIGEST_LENGTH < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha256_ctx));
        hmac_sha3_256_update(&hctx, ivec, 4);
        hmac_sha3_256_final(&hctx, U, SHA3_256_DIGEST_LENGTH);

        /* T_i = U_1 ... */
        memcpy(T, U, SHA3_256_DIGEST_LENGTH);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha3_256_init(&hctx, passwd, passwdlen);
            hmac_sha3_256_update(&hctx, U, SHA3_256_DIGEST_LENGTH);
            hmac_sha3_256_final(&hctx, U, SHA3_256_DIGEST_LENGTH);

            /* ... xor U_j ... */
            for (k = 0; k < SHA3_256_DIGEST_LENGTH; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * SHA3_256_DIGEST_LENGTH;
        if (clen > SHA3_256_DIGEST_LENGTH) {
            clen = SHA3_256_DIGEST_LENGTH;
        }
        memcpy(&buf[i * SHA3_256_DIGEST_LENGTH], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_sha3_256_ctx));
}

/**
 * PBKDF2_SHA512(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA512 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void pbkdf2_sha512(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_sha512_ctx PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[SHA512_DIGEST_SIZE];
    uint8_t T[SHA512_DIGEST_SIZE];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha512_init(&PShctx, passwd, passwdlen);
    hmac_sha512_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * SHA512_DIGEST_SIZE < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha512_ctx));
        hmac_sha512_update(&hctx, ivec, 4);
        hmac_sha512_final(&hctx, U, SHA256_DIGEST_SIZE);

        /* T_i = U_1 ... */
        memcpy(T, U, SHA512_DIGEST_SIZE);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha512_init(&hctx, passwd, passwdlen);
            hmac_sha512_update(&hctx, U, SHA512_DIGEST_SIZE);
            hmac_sha512_final(&hctx, U, SHA512_DIGEST_SIZE);

            /* ... xor U_j ... */
            for (k = 0; k < SHA512_DIGEST_SIZE; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * SHA512_DIGEST_SIZE;
        if (clen > SHA512_DIGEST_SIZE) {
            clen = SHA512_DIGEST_SIZE;
        }
        memcpy(&buf[i * SHA512_DIGEST_SIZE], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_sha512_ctx));
}

/**
 * PBKDF2_SHA512(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA512 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void pbkdf2_sha3_512(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt, size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    hmac_sha3_512_ctx PShctx, hctx;
    size_t i;
    uint8_t ivec[4];
    uint8_t U[SHA3_512_DIGEST_LENGTH];
    uint8_t T[SHA3_512_DIGEST_LENGTH];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_sha3_512_init(&PShctx, passwd, passwdlen);
    hmac_sha3_512_update(&PShctx, salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * SHA3_512_DIGEST_LENGTH < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy(&hctx, &PShctx, sizeof(hmac_sha3_512_ctx));
        hmac_sha3_512_update(&hctx, ivec, 4);
        hmac_sha3_512_final(&hctx, U, SHA3_512_DIGEST_LENGTH);

        /* T_i = U_1 ... */
        memcpy(T, U, SHA3_512_DIGEST_LENGTH);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            hmac_sha3_512_init(&hctx, passwd, passwdlen);
            hmac_sha3_512_update(&hctx, U, SHA3_512_DIGEST_LENGTH);
            hmac_sha3_512_final(&hctx, U, SHA3_512_DIGEST_LENGTH);

            /* ... xor U_j ... */
            for (k = 0; k < SHA3_512_DIGEST_LENGTH; k++) {
                T[k] ^= U[k];
            }
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * SHA3_512_DIGEST_LENGTH;
        if (clen > SHA3_512_DIGEST_LENGTH) {
            clen = SHA3_512_DIGEST_LENGTH;
        }
        memcpy(&buf[i * SHA3_512_DIGEST_LENGTH], T, clen);
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset(&PShctx, 0, sizeof(hmac_sha3_512_ctx));
}
