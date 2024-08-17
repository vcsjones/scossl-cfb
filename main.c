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
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, "AES-128-CFB8", NULL);

    if (cipher == NULL) {
        ERR_print_errors_fp(stdout);
        return 1;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        return 1;
    }

    unsigned char key[16] = { 0 };
    unsigned char iv[16] = { 0 };

    if (!EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    if (!EVP_CIPHER_CTX_set_padding(ctx, 0)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    unsigned char plaintext[1] = { 0x00 };
    int ciphertextLen = 16;
    unsigned char ciphertext[16];


    if (!EVP_EncryptUpdate(ctx, ciphertext, &ciphertextLen, plaintext, sizeof(plaintext))) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    printf("%i\n", ciphertextLen);

    int finalLen = 0;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + ciphertextLen, &finalLen)) {
        ERR_print_errors_fp(stdout);
        EVP_CIPHER_CTX_free(ctx);
        return 1;
    }

    ciphertextLen += finalLen;
    EVP_CIPHER_CTX_free(ctx);

    dump(ciphertext, ciphertextLen);
}