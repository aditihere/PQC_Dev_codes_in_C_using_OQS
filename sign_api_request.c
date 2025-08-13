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


Server (verify_api_request) (another file) verifies the message and signature using the public key.

This mimics how a quantum-safe API client signs requests, and how the server validates 
authenticity and integrity — replacing classical RSA or ECDSA with Dilithium.

  
