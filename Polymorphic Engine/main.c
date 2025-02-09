#include "common.h"
#include "encryption.h"
#include "stub.h"
#include "api.h"

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
    for (size_t i = 0; i < enc_size; i++)
        api.real_printf("%02X ", encrypted[i]);
    api.real_printf("\n");
    
    unsigned char decrypted_soft[MAX_SIZE];
    size_t decrypted_soft_size;
    polymorphic_decrypt(encrypted, enc_size, decrypted_soft, &decrypted_soft_size, method);
    api.real_printf("Software Decryption: %s\n", decrypted_soft);
    
    unsigned char decryptor[MAX_SIZE];
    size_t stub_size;
    generate_stub(decryptor, &stub_size, method, size);
    api.real_printf("Decryptor Stub: ");
    for (size_t i = 0; i < stub_size; i++)
        api.real_printf("%02X ", decryptor[i]);
    api.real_printf("\n");
    
    self_modifying_wrapper(main);
    insert_garbage_blocks();
    
    return 0;
}
