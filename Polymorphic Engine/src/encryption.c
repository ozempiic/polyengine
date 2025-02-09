#include "encryption.h"

void polymorphic_encrypt(unsigned char *payload, size_t size, unsigned char *output, size_t *output_size, EncMethod method) {
    *output_size = 0;
    for (size_t i = 0; i < size; i++) {
        volatile uint32_t dummy = (rand() ^ (uint32_t)i);
        dummy = dummy * 37 + 19;
        unsigned char key = rand() % 256;
        switch(method) {
            case ENC_XOR: 
                output[(*output_size)++] = payload[i] ^ key; 
                break;
            case ENC_ADD: 
                output[(*output_size)++] = (payload[i] + key) % 256; 
                break;
            case ENC_SUB: 
                output[(*output_size)++] = (payload[i] - key) % 256; 
                break;
            case ENC_ROT: 
                output[(*output_size)++] = ((payload[i] << 1) | (payload[i] >> 7)) ^ key;
                break;
        }
        output[(*output_size)++] = key;
    }
}

void polymorphic_decrypt(unsigned char *encrypted, size_t encrypted_size, unsigned char *output, size_t *output_size, EncMethod method) {
    *output_size = 0;
    for (size_t i = 0; i < encrypted_size; i += 2) {
        unsigned char enc_byte = encrypted[i];
        unsigned char key = encrypted[i+1];
        switch(method) {
            case ENC_XOR:
                output[(*output_size)++] = enc_byte ^ key;
                break;
            case ENC_ADD:
                output[(*output_size)++] = (enc_byte - key + 256) % 256;
                break;
            case ENC_SUB:
                output[(*output_size)++] = (enc_byte + key) % 256;
                break;
            case ENC_ROT: {
                unsigned char temp = enc_byte ^ key;
                output[(*output_size)++] = (temp >> 1) | (temp << 7);
                break;
            }
        }
    }
}

/*

void hybrid_encrypt(
    unsigned char *payload, size_t size,
    unsigned char *output, size_t *output_size
) {
    *output_size = 0;
    unsigned char key_xor = random_byte();
    unsigned char key_add = random_byte();
    unsigned char key_rot = (random_byte() & 7) + 1;

    output[(*output_size)++] = key_xor;
    output[(*output_size)++] = key_add;
    output[(*output_size)++] = key_rot;

    for (size_t i = 0; i < size; i++) {
        unsigned char temp = payload[i] ^ key_xor;
        temp = (temp + key_add) % 256;
        temp = (temp << key_rot) | (temp >>  (8 - key_rot));
        output[(*output_size)++] = temp;
    }
}

void hybrid_decrypt(
    unsigned char *encrypted, size_t encrypted_size,
    unsigned char *output, size_t *output_size
) {
    *output_size = 0;
    if (encrypted_size < 3) return;
    unsigned char key_xor = encrypted[0];
    unsigned char key_add = encrypted[1];
    unsigned char key_rot = encrypted[2];

    for (size_t i = 3; i < encrypted_size; i++) {
        unsigned char temp = encrypted[i];
        temp = (temp >> key_rot) | (temp << (8 - key_rot));
        temp = (temp - key_add + 256) % 256;
        temp ^= key_xor;
        output[(*output_size)++] = temp;
    }
    output[*output_size] = '\0';
}

*/