**Build post-quantum secure file encryption** tools using liboqs, we’ll combine a Key Encapsulation Mechanism (KEM) 
like **Kyber** for secure key exchange, and a symmetric cipher like **AES-GCM** for encrypting file contents.

1. Generate a Kyber keypair.

2. Use Kyber encapsulation to securely share a symmetric AES-256 key.

3. Encrypt a file using AES-256-GCM with the shared secret.

4. Save the ciphertext, IV, and tag.

5. Decrypt the file using the same shared secret after decapsulation.



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_KEY_LEN 32
#define AES_IV_LEN 12
#define AES_TAG_LEN 16

void handleErrors(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

int aes_gcm_encrypt(const uint8_t *key, const uint8_t *plaintext, int pt_len,
                    uint8_t *iv, uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ct_len;

    if (!RAND_bytes(iv, AES_IV_LEN)) handleErrors("IV gen failed");

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

int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) handleErrors("KEM init failed");

    // Allocate buffers
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);

    // Generate Kyber keypair and encapsulate
    OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_encaps(kem, ct, ss, pk);

    // Load file content (for demo: hardcoded string)
    const char *filename = "message.txt";
    FILE *f = fopen(filename, "rb");
    if (!f) handleErrors("File open failed");

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *plaintext = malloc(file_size);
    fread(plaintext, 1, file_size, f);
    fclose(f);

    // Encrypt file using AES-GCM with shared secret
    uint8_t iv[AES_IV_LEN], tag[AES_TAG_LEN];
    uint8_t *ciphertext = malloc(file_size + AES_TAG_LEN);
    int ct_len = aes_gcm_encrypt(ss, plaintext, file_size, iv, ciphertext, tag);

    // Save encrypted file
    FILE *out = fopen("encrypted.bin", "wb");
    fwrite(iv, 1, AES_IV_LEN, out);
    fwrite(tag, 1, AES_TAG_LEN, out);
    fwrite(ciphertext, 1, ct_len, out);
    fclose(out);

    printf("Encrypted '%s' using Kyber+AES and saved as 'encrypted.bin'\n", filename);

    // Cleanup
    free(pk); free(sk); free(ct); free(ss);
    free(plaintext); free(ciphertext);
    OQS_KEM_free(kem);
    return 0;
}


echo "This is a post-quantum secure message." > message.txt
