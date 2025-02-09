#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include "common.h"

void polymorphic_encrypt(unsigned char *payload, size_t size, unsigned char *output, size_t *output_size, EncMethod method);
void polymorphic_decrypt(unsigned char *encrypted, size_t encrypted_size, unsigned char *output, size_t *output_size, EncMethod method);

#endif // ENCRYPTION_H
