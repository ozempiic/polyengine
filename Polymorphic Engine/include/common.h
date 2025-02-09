#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <stdint.h>

#define MAX_SIZE 1024
#define XOR_KEY 0xAA
#define API_HASH_SEED 0xDEADBEEF

typedef enum { 
    ENC_XOR, 
    ENC_ADD, 
    ENC_SUB, 
    ENC_ROT 
} EncMethod;

typedef struct {
    EncMethod method;
    uint8_t decrypt_opcode;
    uint8_t stub_register_mask;
} MethodConfig;

extern const MethodConfig ENCRYPTED_METHODS[];

typedef struct {
    void (*decoy1)(int);
    void (*real_printf)(const char *, ...);
    void (*decoy2)(void*);
    char dummy[16];
} ObfuscatedAPI;

extern ObfuscatedAPI api;

typedef struct {
    uint8_t part1[7];
    uint8_t part2[6];
    uint8_t xor_key;
} ObfuscatedPayload;

extern const ObfuscatedPayload OBFS_PAYLOAD;

uint32_t compute_hash(const char *str, uint32_t seed);

#endif // COMMON_H
