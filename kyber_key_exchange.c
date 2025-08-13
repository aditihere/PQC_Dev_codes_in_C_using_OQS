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
