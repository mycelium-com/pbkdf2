#include "pbkdf.h"

#include <string.h>
#include <stdio.h>

const uint64_t iterations = 20000u;
const unsigned char passwd[14] = "TEST_PASSWORD";
const uint8_t salt[8] = {0xE1, 0xF5, 0x31, 0x35, 0xE5, 0x59, 0xC2, 0x53};
uint8_t secret[64] = {0};

static void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

struct testVector {
    const char *password;
    const int password_len;
    const char *salt;
    const int salt_len;
    const int iterations;
    const int dkLen;
};

struct testVector test256[6] = {
    { "password"                 , 8,   "salt"                                 , 4,  1, 32 },
    { "password"                 , 8,   "salt"                                 , 4,  2, 32 },
    { "password"                 , 8,   "salt"                                 , 4,  4096, 32 },
    { "password"                 , 8,   "salt"                                 , 4,  16777216, 32 },
    { "passwordPASSWORDpassword" , 24,  "saltSALTsaltSALTsaltSALTsaltSALTsalt" , 36, 4096, 40 },
    { "pass\0word"               , 9,   "sa\0lt"                               , 5,  4096, 16 },
};

struct testVector test512[5] = {
    { "password"                 , 8,   "salt"                                 , 4,  1, 64 },
    { "password"                 , 8,   "salt"                                 , 4,  2, 64 },
    { "password"                 , 8,   "salt"                                 , 4,  4096, 64 },
    { "passwordPASSWORDpassword" , 24,  "saltSALTsaltSALTsaltSALTsaltSALTsalt" , 36, 4096, 64 },
};


int main() {
    // Array for generated keys
    uint8_t secret[128];


    printf("Testing PBKDF2-HMAC-SHA3-256 against test vectors\n:");
    
    for (int i = 0; i < 6; ++i) {
        const char *password = test256[i].password;
        const int password_len = test256[i].password_len;
        const char *salt = test256[i].salt;
        const int salt_len = test256[i].salt_len;
        const int iterations = test256[i].iterations;
        const int dkLen = test256[i].dkLen;

        pbkdf2_sha3_256((const uint8_t*) password, password_len, (const uint8_t*) salt, salt_len, iterations, secret, dkLen);

        printf("Derived key (hmac-sha256, vector %d): ", i);
        print(secret, dkLen);
        printf("\n");
    }

    printf("Testing PBKDF2-HMAC-SHA3-512 against test vectors\n:");

    for (int i = 0; i < 4; ++i) {
        const char *password = test512[i].password;
        const int password_len = test512[i].password_len;
        const char *salt = test512[i].salt;
        const int salt_len = test512[i].salt_len;
        const int iterations = test512[i].iterations;
        const int dkLen = test512[i].dkLen;

        pbkdf2_sha3_512((const uint8_t*) password, password_len, (const uint8_t*) salt, salt_len, iterations, secret, dkLen);
        printf("Derived key (hmac-sha512, vector %d): ", i);
        print(secret, dkLen);
        printf("\n");
    }

    return 0;
}
