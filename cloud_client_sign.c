Implement PQC-based authentication for a cloud application using liboqs (Dilithium3 signatures)

Cloud client: signs a login or API request → sends it  to server

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
