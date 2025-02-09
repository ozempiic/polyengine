#ifndef STUB_H
#define STUB_H

#include "common.h"

void insert_garbage_blocks();
void insert_garbage(unsigned char **stub, int count);
void self_modifying_wrapper(int (*func)());
void generate_stub(unsigned char *stub, size_t *size, EncMethod method, int payload_size);

#endif // STUB_H
