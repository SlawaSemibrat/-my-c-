#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <string.h>
#include <fstream>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) // вход - текст, длина текста, ключ, вектор, масив в который записывается шифрованный текст.
{
    EVP_CIPHER_CTX *ctx;

    int len;

    (ctx = EVP_CIPHER_CTX_new());

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

}

void newMessage(unsigned char *message, unsigned char *tag, unsigned char *plaintext2) // вход - сообщение m, тэг , масив в который записывается m'.
{
	std::string newMessage(32, ' ');

	for (int i = 0; i < AES_BLOCK_SIZE; i++)
	  newMessage[i] = (unsigned char)(message[i]);
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
		newMessage[i+AES_BLOCK_SIZE] = (unsigned char)(message[i] ^ tag[i]);

	strcpy((char*)plaintext2, newMessage.c_str());
}

void tagGen(unsigned char *message, unsigned char *tag)// вход - сообщение, массив в который записывается тэг
{
  for (int i = 0; i < AES_BLOCK_SIZE; i++)
	 tag[i] = (unsigned char)(message[i]);
}


int authentication (unsigned char *tag1,   unsigned char *tag2){
  int i=0;
  while(tag1[i]==tag2[i]){
    i++;
  }
  if(i==AES_BLOCK_SIZE)
    return 1;
  else
    return 0;
}

int main (void)
{

    unsigned char key[AES_BLOCK_SIZE];
    RAND_bytes(key, AES_BLOCK_SIZE);

    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int lenPlaintext = AES_BLOCK_SIZE*2;

    unsigned char *plaintext = (unsigned char *)"12345678901234567890123456789012";
    unsigned char plaintext2[lenPlaintext];

    unsigned char cipherTextOut [lenPlaintext];
    unsigned char cipherTextOut2 [lenPlaintext];


    unsigned char cipherTextIn [lenPlaintext];

    unsigned char ciphertext[lenPlaintext];

    unsigned char decryptedtext[lenPlaintext];

    encrypt (plaintext, lenPlaintext , key, iv, cipherTextOut);

    unsigned char tag1[AES_BLOCK_SIZE];
    unsigned char tag2[AES_BLOCK_SIZE];

    tagGen(cipherTextOut,tag1);

    newMessage(plaintext,tag1,plaintext2);

    tag1[AES_BLOCK_SIZE] = '\0';

    std::cout << "message :"<<plaintext<< '\n'<<"message':" <<plaintext2<< '\n';

    encrypt (plaintext2, lenPlaintext , key, iv, cipherTextOut2);

     printf("tag1 :");
     printf("%s\n", tag1);

    tagGen(cipherTextOut2,tag2);

     printf("tag2 :");
     printf("%s\n", tag2);
     printf("\n");

    if(authentication(tag1, tag2)==1)
      printf("V(m', t, k) = accept");
    else
      printf("V(m', t, k) = denaid");

    return 0;
}
