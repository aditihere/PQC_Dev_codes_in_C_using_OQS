encrypt & decrypt message using that key from the file Vpn_keyexchange.c


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32    // Use first 32 bytes of Kyber shared key
#define AES_IV_LEN 12
#define AES_TAG_LEN 16

void handleErrors(const char *msg) {
    fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE);
}

// AES-GCM encryption
int aes_gcm_encrypt(const uint8_t *key, const uint8_t *plaintext, int pt_len,
                    uint8_t *iv, uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ct_len;

    if (!RAND_bytes(iv, AES_IV_LEN)) handleErrors("IV generation failed");
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    ct_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ct_len;
}

// AES-GCM decryption
int aes_gcm_decrypt(const uint8_t *key, const uint8_t *ciphertext, int ct_len,
                    const uint8_t *iv, const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, pt_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, (void*)tag);
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        handleErrors("Decryption failed: tag mismatch");
    }
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return pt_len;
}

int main() {
    // Load shared AES key
    FILE *f = fopen("vpn_aes_key.bin", "rb");
    uint8_t shared_key[AES_KEY_LEN];
    fread(shared_key, 1, AES_KEY_LEN, f);
    fclose(f);

    // Encrypt message
    const char *msg = "Hello from quantum-safe VPN!";
    uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
    uint8_t ciphertext[128], decrypted[128];
    int ct_len = aes_gcm_encrypt(shared_key, (const uint8_t*)msg, strlen(msg), iv, ciphertext, tag);

    printf("Encrypted message length: %d\n", ct_len);

    // Decrypt
    int pt_len = aes_gcm_decrypt(shared_key, ciphertext, ct_len, iv, tag, decrypted);
    decrypted[pt_len] = '\0';  // Null-terminate

    printf("Decrypted message: %s\n", decrypted);
    return 0;
}
