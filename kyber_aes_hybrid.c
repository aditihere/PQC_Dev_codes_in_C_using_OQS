#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void print_hex(const char *label, const uint8_t *buf, size_t len) {
    printf("%s [%zu bytes]: ", label, len);
    for (size_t i = 0; i < len; i++) printf("%02X", buf[i]);
    printf("\n");
}

// AES-GCM encryption
int aes_encrypt(const uint8_t *key, const uint8_t *plaintext, size_t pt_len,
                uint8_t *ciphertext, uint8_t *tag, uint8_t *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES-GCM decryption
int aes_decrypt(const uint8_t *key, const uint8_t *ciphertext, size_t ct_len,
                const uint8_t *tag, uint8_t *plaintext, uint8_t *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, pt_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ret > 0 ? pt_len : -1; // -1 on failure
}

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss_enc = malloc(kem->length_shared_secret);
    uint8_t *ss_dec = malloc(kem->length_shared_secret);

    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    OQS_KEM_decaps(kem, ss_dec, ct, sk);

    print_hex("Shared Secret (Sender)", ss_enc, 32);
    print_hex("Shared Secret (Receiver)", ss_dec, 32);

    // === AES-GCM Encryption using shared key ===
    uint8_t key[32];
    memcpy(key, ss_enc, 32);

    uint8_t plaintext[] = "Post-quantum encryption is real!";
    uint8_t ciphertext[128], tag[16], iv[12];
    RAND_bytes(iv, sizeof(iv)); // random IV

    int ct_len = aes_encrypt(key, plaintext, strlen((char *)plaintext), ciphertext, tag, iv);

    printf("\n Encrypted Message:\n");
    print_hex("Ciphertext", ciphertext, ct_len);
    print_hex("Tag", tag, 16);
    print_hex("IV", iv, 12);

    // === AES-GCM Decryption using shared key ===
    uint8_t decrypted[128];
    int pt_len = aes_decrypt(ss_dec, ciphertext, ct_len, tag, decrypted, iv);

    if (pt_len > 0) {
        decrypted[pt_len] = '\0';
        printf("\n Decrypted message: %s\n", decrypted);
    } else {
        printf("Decryption failed!\n");
    }

    // Cleanup
    free(pk); free(sk); free(ct); free(ss_enc); free(ss_dec);
    OQS_KEM_free(kem);
    return 0;
}