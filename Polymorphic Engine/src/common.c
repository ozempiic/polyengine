#include "common.h"

const MethodConfig ENCRYPTED_METHODS[] = {
    {ENC_XOR, 0x32 ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_ADD, 0x2A ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_SUB, 0x2A ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_ROT, 0xC0 ^ XOR_KEY, 0x40 ^ XOR_KEY},
};

ObfuscatedAPI api = {0};

const ObfuscatedPayload OBFS_PAYLOAD = {
    {0x53 ^ XOR_KEY, 0x65 ^ XOR_KEY, 0x63 ^ XOR_KEY, 0x72 ^ XOR_KEY, 0x65 ^ XOR_KEY, 0x74 ^ XOR_KEY, 0x50 ^ XOR_KEY},
    {0x61 ^ XOR_KEY, 0x79 ^ XOR_KEY, 0x6C ^ XOR_KEY, 0x6F ^ XOR_KEY, 0x61 ^ XOR_KEY, 0x64 ^ XOR_KEY},
    XOR_KEY
};

uint32_t compute_hash(const char *str, uint32_t seed) {
    uint32_t hash = seed;
    while (*str) {
        hash = (hash ^ (*str)) + ((hash << 26) | (hash >> 6));
        str++;
    }
    return hash;
}