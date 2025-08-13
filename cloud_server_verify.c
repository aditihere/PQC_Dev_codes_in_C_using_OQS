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