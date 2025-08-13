Two parties exchange a Kyber key & derive shared key for VPN tunnel

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
