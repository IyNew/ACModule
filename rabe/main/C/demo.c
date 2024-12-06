#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "demo.h"  // Replace with the path to rabe.h in your project

extern const void* rabe_aw11_init();
extern struct Aw11AuthGenResult rabe_cp_aw11_generate_auth(const void *global_key, const char *const *attrs, uintptr_t attr_len);
extern const void* rabe_cp_aw11_generate_secret_key(const void* global_key, const void* master_key, const char* name, const char*const *attrs, uintptr_t attr_len);
extern const void* rabe_cp_aw11_encrypt(const void* global_key, const void*const *public_keys, uintptr_t public_keys_len, const char* policy, const char* text, uintptr_t text_length);
extern struct CBoxedBuffer rabe_cp_aw11_decrypt(const void* global_key, const void* secret_key, const void* cipher);

extern void rabe_cp_aw11_free_master_key(const void* master_key);
extern void rabe_cp_aw11_free_public_key(const void* public_key);
extern void rabe_cp_aw11_free_secret_key(const void* secret_key);
extern void rabe_cp_aw11_free_ciphertext(const void* cipher);
extern void rabe_free_boxed_buffer(struct CBoxedBuffer buffer);

void print_decrypted_text(const struct CBoxedBuffer* buffer) {
    printf("Decrypted text: ");
    for (size_t i = 0; i < buffer->len; i++) {
        putchar(buffer->buffer[i]);
    }
    printf("\n");
}
void write_master_key_result_to_file(const struct Aw11AuthGenResult* auth_result, const char* filename, size_t key_size){
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    fwrite(auth_result->master_key, sizeof(int), key_size, file);
    //fwrite(auth_result->public_key, sizeof(int), key_size, file);
    fclose(file);
    printf("AuthGenResult data written to file '%s' successfully.\n", filename);
}
void write_pub_key_result_to_file(const struct Aw11AuthGenResult* auth_result, const char* filename, size_t key_size){
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        perror("Failed to open file");
        return;
    }
    fwrite(auth_result->public_key, sizeof(int), key_size, file);
    fclose(file);
    printf("AuthGenResult data written to file '%s' successfully.\n", filename);
}
int main() {
    const void* global_key = rabe_aw11_init();
    if (!global_key) {
        fprintf(stderr, "Failed to initialize global key.\n");
        return 1;
    }

    const char* attrs[] = {"A", "B"};
    size_t attr_len = 2;

    struct Aw11AuthGenResult auth_keys = rabe_cp_aw11_generate_auth(global_key, attrs, attr_len);
    if (!auth_keys.master_key || !auth_keys.public_key) {
        fprintf(stderr, "Failed to generate authority keys.\n");
        return 1;
    }

    write_master_key_result_to_file(&auth_keys, "master_key.bin", 1);
    write_pub_key_result_to_file(&auth_keys, "public_key.bin", 1);    
    
    
    const char* name = "A";
    const void* secret_key = rabe_cp_aw11_generate_secret_key(global_key, (void*)auth_keys.master_key, name, attrs, attr_len);
    if (!secret_key) {
        fprintf(stderr, "Failed to generate secret key.\n");
        return 1;
    }

    const char* policy = "\"A\" and \"B\"";
    const char* plaintext = "hello world";
    size_t plaintext_len = strlen(plaintext);

    const void* public_keys[] = {auth_keys.public_key};
    const void* cipher = rabe_cp_aw11_encrypt(global_key, public_keys, 1, policy, plaintext, plaintext_len);
    if (!cipher) {
        fprintf(stderr, "Failed to encrypt the plaintext.\n");
        return 1;
    }

    struct CBoxedBuffer decrypted = rabe_cp_aw11_decrypt(global_key, secret_key, cipher);
    if (!decrypted.buffer) {
        fprintf(stderr, "Failed to decrypt the ciphertext.\n");
        return 1;
    }

    print_decrypted_text(&decrypted);

    rabe_cp_aw11_free_master_key((void*)auth_keys.master_key);
    rabe_cp_aw11_free_public_key((void*)auth_keys.public_key);
    rabe_cp_aw11_free_secret_key(secret_key);
    rabe_cp_aw11_free_ciphertext(cipher);
    rabe_free_boxed_buffer(decrypted);

    return 0;
}
