#include "pbkdf.h"

#include <string.h>
#include <stdio.h>

const uint64_t iterations = 20000u;
const unsigned char passwd[14] = "TEST_PASSWORD";
const uint8_t salt[8] = {0xE1, 0xF5, 0x31, 0x35, 0xE5, 0x59, 0xC2, 0x53};
uint8_t secret[32];

static void print(const uint8_t *data, int length) {
    for (int i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
}

int main() {
    pbkdf2_sha3_256(passwd, sizeof(passwd), salt, sizeof(salt), iterations, secret, sizeof(secret));

    printf("Derived key: ");
    print(secret, sizeof(secret));
    printf("\n");

    return 0;
}
