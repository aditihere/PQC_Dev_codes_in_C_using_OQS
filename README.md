# Post-Quantum Cryptography Development in C using Open Quantum Safe (OQS)

KYBER KEY EXCAHNGE CODES !!


```python
#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_KEM_alg_is_enabled(OQS_KEM_alg_kyber_512)) {
        printf("Kyber512 not enabled in this build.\n");
        return EXIT_FAILURE;
    }

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        printf("Failed to initialize Kyber512 KEM.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(kem->length_public_key);
    uint8_t *secret_key = malloc(kem->length_secret_key);
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *shared_secret_enc = malloc(kem->length_shared_secret);
    uint8_t *shared_secret_dec = malloc(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret_enc, public_key) != OQS_SUCCESS) {
        printf("Encapsulation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_KEM_decaps(kem, shared_secret_dec, ciphertext, secret_key) != OQS_SUCCESS) {
        printf("Decapsulation failed.\n");
        return EXIT_FAILURE;
    }

    if (memcmp(shared_secret_enc, shared_secret_dec, kem->length_shared_secret) == 0) {
        printf("Kyber512 Key Exchange Success! Shared secrets match.\n");
    } else {
        printf(" Shared secrets do NOT match!\n");
    }

    // Cleanup
    OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    return 0;
}

```


```python
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

```

DILITHIUM SIGNATURE VERIFICATION CODE


```python
#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        printf("Dilithium3 not enabled in this build.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        printf("Failed to initialize Dilithium3.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;
    uint8_t message[] = "Post-Quantum Signatures are here!";
    size_t message_len = strlen((char *)message);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
        printf("Signing failed.\n");
        return EXIT_FAILURE;
    }

    OQS_STATUS verify_status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    if (verify_status == OQS_SUCCESS) {
        printf("Dilithium3 Signature Verified Successfully.\n");
    } else {
        printf(" Signature Verification Failed!\n");
    }

    // Cleanup
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}
```

Falcon Sinature Verification


```python
#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_falcon_512)) {
        printf("Falcon-512 not enabled in this build.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        printf("Failed to initialize Falcon-512.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;
    uint8_t message[] = "Falcon is compact and efficient!";
    size_t message_len = strlen((char *)message);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
        printf("Signing failed.\n");
        return EXIT_FAILURE;
    }

    OQS_STATUS verify_status = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    if (verify_status == OQS_SUCCESS) {
        printf("Falcon-512 Signature Verified Successfully.\n");
    } else {
        printf("Falcon-512 Signature Verification Failed!\n");
    }

    // Cleanup
    OQS_SIG_free(sig);
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}

```

**Timing comparison test between a valid and an invalid signature**  to check for potential timing side-channels.


```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        printf("Dilithium3 not enabled in this build.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        printf("Failed to initialize Dilithium3.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len = 0;
    uint8_t message[] = "Timing test for signature verification.";
    size_t message_len = strlen((char *)message);

    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        printf("Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    if (OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
        printf("Signing failed.\n");
        return EXIT_FAILURE;
    }

    // Timing: valid signature
    clock_t t1 = clock();
    OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    clock_t t2 = clock();

    // Corrupt the signature
    signature[0] ^= 0xAA;

    // Timing: invalid signature
    clock_t t3 = clock();
    OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key);
    clock_t t4 = clock();

    printf("Valid Signature Verification:   %ld ticks\n", t2 - t1);
    printf("Invalid Signature Verification: %ld ticks\n", t4 - t3);

    // Cleanup
    free(public_key);
    free(secret_key);
    free(signature);
    OQS_SIG_free(sig);

    return 0;
}

```

**Build post-quantum secure file encryption** tools using liboqs, we’ll combine a Key Encapsulation Mechanism (KEM) like **Kyber** for secure key exchange, and a symmetric cipher like **AES-GCM** for encrypting file contents.

1. Generate a Kyber keypair.

2. Use Kyber encapsulation to securely share a symmetric AES-256 key.

3. Encrypt a file using AES-256-GCM with the shared secret.

4. Save the ciphertext, IV, and tag.

5. Decrypt the file using the same shared secret after decapsulation.


```python
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

```


```python
echo "This is a post-quantum secure message." > message.txt
```

Client Code (sign_api_request.c):
Initializes Dilithium3 via OQS_SIG_new.

Generates a public-private keypair using OQS_SIG_keypair.

Signs a fixed message like "POST:/api/data" using the private key.

Writes the following to a file:

The public key (for verification)

The message

The signature

This file acts like an authenticated API request.

Server Code (verify_api_request.c):
Loads the public key and signature from the file.

Assumes the same fixed message ("POST:/api/data") as the one signed by the client.

Verifies the signature using OQS_SIG_verify.

If the signature is valid, the request is authentic and hasn’t been tampered with.


Goal:
Simulate an API authentication workflow where:

Client (sign_api_request) signs a message (like POST:/api/data) using its private key.

Server (verify_api_request) verifies the message and signature using the public key.

This mimics how a quantum-safe API client signs requests, and how the server validates authenticity and integrity — replacing classical RSA or ECDSA with Dilithium.


```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        printf("Dilithium3 not enabled.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        printf("Failed to initialize signature algorithm.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    // Message to sign
    const uint8_t message[] = "POST:/api/data";
    size_t message_len = strlen((const char *)message);

    OQS_SIG_keypair(sig, public_key, secret_key);
    OQS_SIG_sign(sig, signature, &signature_len, message, message_len, secret_key);

    // Write public key, message, signature to file
    FILE *f = fopen("signed_request.bin", "wb");
    fwrite(public_key, 1, sig->length_public_key, f);
    fwrite(message, 1, message_len, f);
    fwrite(signature, 1, signature_len, f);
    fclose(f);

    printf("API request signed and written to 'signed_request.bin'\n");

    free(public_key); free(secret_key); free(signature); OQS_SIG_free(sig);
    return 0;
}

```


```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        printf("Dilithium3 not enabled.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (sig == NULL) {
        printf("Failed to initialize signature algorithm.\n");
        return EXIT_FAILURE;
    }

    FILE *f = fopen("signed_request.bin", "rb");
    if (!f) {
        printf("Could not open signed_request.bin\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    fread(public_key, 1, sig->length_public_key, f);

    // Assume fixed message
    const uint8_t expected_message[] = "POST:/api/data";
    size_t message_len = strlen((const char *)expected_message);

    // Read signature from file
    uint8_t *signature = malloc(sig->length_signature);
    fread(NULL, 1, message_len, f);  // Skip message (we already know it)
    fread(signature, 1, sig->length_signature, f);
    fclose(f);

    if (OQS_SIG_verify(sig, expected_message, message_len, signature, sig->length_signature, public_key) == OQS_SUCCESS) {
        printf("Signature verified. API request is authentic.\n");
    } else {
        printf("Signature verification failed. Request is not authentic.\n");
    }

    free(public_key); free(signature); OQS_SIG_free(sig);
    return 0;
}

```

Vpn_keyexchange.c – two parties exchange a Kyber key & derive shared key for VPN tunnel



```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

// Simulate: client sends ciphertext to server, both derive same shared secret
int main() {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) { printf("KEM init failed\n"); return EXIT_FAILURE; }

    // === Server side generates keypair ===
    uint8_t *server_pk = malloc(kem->length_public_key);
    uint8_t *server_sk = malloc(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, server_pk, server_sk) != OQS_SUCCESS) {
        printf("Server keypair generation failed\n"); return EXIT_FAILURE;
    }

    // === Client encapsulates ===
    uint8_t *ciphertext = malloc(kem->length_ciphertext);
    uint8_t *client_shared_secret = malloc(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, ciphertext, client_shared_secret, server_pk) != OQS_SUCCESS) {
        printf("Client encapsulation failed\n"); return EXIT_FAILURE;
    }

    // === Server decapsulates ===
    uint8_t *server_shared_secret = malloc(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, server_shared_secret, ciphertext, server_sk) != OQS_SUCCESS) {
        printf("Server decapsulation failed\n"); return EXIT_FAILURE;
    }

    // === Compare ===
    if (memcmp(client_shared_secret, server_shared_secret, kem->length_shared_secret) == 0) {
        printf("VPN key exchange success! Shared AES key established.\n");
    } else {
        printf("Shared keys do not match!\n");
    }

    // === Save shared key for later ===
    FILE *f = fopen("vpn_aes_key.bin", "wb");
    fwrite(server_shared_secret, 1, kem->length_shared_secret, f);
    fclose(f);

    free(server_pk); free(server_sk); free(ciphertext);
    free(client_shared_secret); free(server_shared_secret);
    OQS_KEM_free(kem);
    return 0;
}

```

Secure_message.c – encrypt & decrypt message using that key


```python
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

```

Implement PQC-based authentication for a cloud application using liboqs (Dilithium3 signatures)

Cloud client: signs a login or API request → sends it to server


```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        fprintf(stderr, "Dilithium3 not enabled.\n");
        return EXIT_FAILURE;
    }

    // Initialize Dilithium3 signature object
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        fprintf(stderr, "Failed to initialize Dilithium3.\n");
        return EXIT_FAILURE;
    }

    // Allocate buffers
    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    // Generate keypair
    if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Keypair generation failed.\n");
        return EXIT_FAILURE;
    }

    // Example request: POST to /api/user/login
    const uint8_t request[] = "POST:/api/user/login";
    size_t request_len = strlen((const char*)request);

    // Sign the request
    if (OQS_SIG_sign(sig, signature, &signature_len, request, request_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Signing failed.\n");
        return EXIT_FAILURE;
    }

    // Save to file: public key, request, signature
    FILE *out = fopen("signed_request.bin", "wb");
    if (!out) {
        fprintf(stderr, "Failed to open output file.\n");
        return EXIT_FAILURE;
    }
    fwrite(public_key, 1, sig->length_public_key, out);
    fwrite(request, 1, request_len, out);
    fwrite(signature, 1, signature_len, out);
    fclose(out);

    printf("Client: request signed & saved to 'signed_request.bin'\n");

    free(public_key); free(secret_key); free(signature);
    OQS_SIG_free(sig);
    return 0;
}

```

Cloud server: checks signature before accepting the request


```python
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <oqs/oqs.h>

int main() {
    if (!OQS_SIG_alg_is_enabled(OQS_SIG_alg_dilithium_3)) {
        fprintf(stderr, "Dilithium3 not enabled.\n");
        return EXIT_FAILURE;
    }

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_3);
    if (!sig) {
        fprintf(stderr, "Failed to initialize Dilithium3.\n");
        return EXIT_FAILURE;
    }

    FILE *in = fopen("signed_request.bin", "rb");
    if (!in) {
        fprintf(stderr, "Failed to open signed request.\n");
        return EXIT_FAILURE;
    }

    // Read public key
    uint8_t *public_key = malloc(sig->length_public_key);
    fread(public_key, 1, sig->length_public_key, in);

    // Read request
    const size_t request_len = strlen("POST:/api/user/login");
    uint8_t request[request_len];
    fread(request, 1, request_len, in);

    // Read signature
    uint8_t *signature = malloc(sig->length_signature);
    fread(signature, 1, sig->length_signature, in);
    fclose(in);

    // Verify signature
    if (OQS_SIG_verify(sig, request, request_len, signature, sig->length_signature, public_key) == OQS_SUCCESS) {
        printf("Server: request verified successfully! Authenticated.\n");
    } else {
        printf("Server: verification failed! Reject request.\n");
    }

    free(public_key); free(signature);
    OQS_SIG_free(sig);
    return 0;
}

```
