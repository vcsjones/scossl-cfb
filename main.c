#include <openssl/evp.h>
#include <openssl/err.h>

void dump(unsigned char* data, int length) {
    for (int i = 0; i < length; i++) {
        unsigned char e = data[i];
        printf("%#04x ", e);
    }

    printf("%s", "\n");
}

int main() {
    const EVP_CIPHER* cipher = EVP_aes_128_cfb128();

    if (cipher == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    EVP_CIPHER_CTX*  ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return 1;
    }

    unsigned char key[16] = { 0 };
    unsigned char iv[16] = { 0 };

    if (!EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    unsigned char destination[16] = { 0 };
    int destinationLen = 16;
    unsigned char ciphertext[0];
    int ciphertextLen = 0;

    if (!EVP_DecryptUpdate(ctx, destination, &destinationLen, ciphertext, ciphertextLen)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    printf("%s\n", "Done.");
}