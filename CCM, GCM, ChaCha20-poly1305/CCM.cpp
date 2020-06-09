#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <iostream>

int tag_len = 14;

void keyGen(unsigned char *key){
    RAND_bytes(key, 256);
}

int ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len, ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL);

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ccm(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag);

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len);

    EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len);

    ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

    plaintext_len = len;

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
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

    unsigned char *plaintext = (unsigned char *)"12345678901234567890123456789";

    unsigned char *additional = (unsigned char *)"12345678901234567890";

    unsigned char ciphertext[strlen ((char *)plaintext)];

    unsigned char decryptedtext[strlen ((char *)plaintext)];

    unsigned char tag[tag_len];

    int decryptedtext_len, ciphertext_len;

    ciphertext_len = ccm_encrypt(plaintext,
                                 strlen ((char *)plaintext),
                                 additional,
                                 strlen ((char *)additional),
                                 key,
                                 iv,
                                 ciphertext, tag);

    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    printf("Tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, tag_len);

    decryptedtext_len = ccm_decrypt(ciphertext,
                                    ciphertext_len,
                                    additional,
                                    strlen ((char *)additional),
                                    tag,
                                    key, iv,
                                    decryptedtext);
                                    
    if (decryptedtext_len >= 0) {
        decryptedtext[decryptedtext_len] = '\0';
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

    printf("\nModified tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, tag_len);

    decryptedtext_len = ccm_decrypt(ciphertext, ciphertext_len,
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv,
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
