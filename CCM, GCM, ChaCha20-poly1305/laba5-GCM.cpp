#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <iostream>

void keyGen(unsigned char *key){
    RAND_bytes(key, 256);
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len, plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL);

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)  ;

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}

int main (void)
{

    unsigned char key[256];
    keyGen(key);

    unsigned char *iv = (unsigned char *)"0123456789012345";
    size_t iv_len = 16;

    unsigned char *plaintext = (unsigned char *)"Tdfsdfsdfsd dfsdfsdfsd sfds hhh";

    unsigned char *additional = (unsigned char *)"The five boxing wizards jump quickly.";

    unsigned char ciphertext[strlen ((char *)plaintext)];

    unsigned char decryptedtext[strlen ((char *)plaintext)];

    unsigned char tag[16];

    int decryptedtext_len, ciphertext_len;


    ciphertext_len = gcm_encrypt(plaintext,
                                 strlen ((char *)plaintext),
                                 additional,
                                 strlen ((char *)additional),
                                 key,
                                 iv, iv_len,
                                 ciphertext, tag);

    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    printf("Tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, 16);

    decryptedtext_len = gcm_decrypt(ciphertext,
                                    ciphertext_len,
                                    additional,
                                    strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

    printf("\nModified tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, 16);

    decryptedtext_len = gcm_decrypt(ciphertext,
                                    ciphertext_len,
                                    additional,
                                    strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

    return 0;
}
