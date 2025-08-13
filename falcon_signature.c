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
