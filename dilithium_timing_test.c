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
