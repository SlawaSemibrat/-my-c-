#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <iostream>


int ivleen = 9;
int GET_TAG = 16;
int SET_TAG = 17;


void keyGen(unsigned char *key){
    RAND_bytes(key, 256);
}

int ChaCha20_Poly1305_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len,ciphertext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, ivleen, 7, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, SET_TAG, GET_TAG, NULL);

    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len);

    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, GET_TAG, GET_TAG, tag);

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ChaCha20_Poly1305_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{

    EVP_CIPHER_CTX *ctx;
    int len,plaintext_len, ret;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx,EVP_chacha20_poly1305(), NULL, NULL, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, ivleen, 7, NULL);

    EVP_CIPHER_CTX_ctrl(ctx, SET_TAG, GET_TAG, tag);

    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

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


      unsigned char *additional = (unsigned char *)"The five boxing wizards jump quickly.";


      unsigned char ciphertext[strlen ((char *)plaintext)];

      unsigned char decryptedtext[strlen ((char *)plaintext)];

      unsigned char tag[GET_TAG];

      int decryptedtext_len, ciphertext_len;


      ciphertext_len = ChaCha20_Poly1305_encrypt(plaintext, strlen ((char *)plaintext),
                                   additional, strlen ((char *)additional),
                                   key,
                                   iv,
                                   ciphertext, tag);

      printf("Ciphertext is:\n");
      BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

      printf("Tag is:\n");
      BIO_dump_fp (stdout, (const char *)tag, GET_TAG);


      decryptedtext_len = ChaCha20_Poly1305_decrypt(ciphertext, ciphertext_len,
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


      printf("\nModified tag is:\n");
      BIO_dump_fp (stdout, (const char *)tag, GET_TAG);

      decryptedtext_len = ChaCha20_Poly1305_decrypt(ciphertext, ciphertext_len,
                                      additional, strlen ((char *)additional),
                                      tag,
                                      key, iv,
                                      decryptedtext);

      if (decryptedtext_len >= 0) {

          decryptedtext[decryptedtext_len] = '\0';
          printf("\nMessage accept - ");
          printf("Decrypted text is: ");
          printf("%s\n", decryptedtext);
      } else {
          printf("Accept denied\n");
      }

      return 0;
  }
