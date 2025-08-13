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
