#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>

int sizeOfPlaintext() // выход - количество символов в файле input.
{
  int count=0;
  char a;
    std::ifstream r;
    r.open("/home/clawa/ff/input.txt");
    while (!r.eof())
    {
        count++;
        a=r.get();
    }
    r.close();
    return count-1;
}

void readInFile(unsigned char *ctext) //записываем содержимае файла в массив на входе
{
  FILE *f2 = std::fopen("/home/clawa/ff/input.txt", "rb") ;
  fread(ctext, sizeof(unsigned char), sizeOfPlaintext(), f2);
  fclose(f2);
}

void fileFill(unsigned char *ctext) // записывает в файл зашированный текст. Вход- ммассив который нужно записать
{
  FILE* f = std::fopen("/home/clawa/ff/output.txt", "wb");
  fwrite(ctext, sizeof(unsigned char), sizeOfPlaintext(), f);
  fclose (f);
}

void encFileRead(unsigned char *ctext) //получает масив и на выходе и заполняет его данными из зашифрованног файла
{
  FILE *f3 = std::fopen("/home/clawa/ff/output.txt", "rb") ;
  fread(ctext, sizeof(unsigned char), sizeOfPlaintext(), f3);
  fclose(f3);
}

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

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)// вход - зашифрованный текст, длина текста, ключ, вектор, масив в который записывается расшифрованный текст.
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);


    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);


    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);


    EVP_CIPHER_CTX_free(ctx);
}

int main (void)
{
    std::cout << "/* message */" << '\n';
    unsigned char key[AES_BLOCK_SIZE];
    RAND_bytes(key, AES_BLOCK_SIZE);

    unsigned char iv[AES_BLOCK_SIZE/2];
    RAND_bytes(iv,AES_BLOCK_SIZE);
std::cout << "/* message */" << '\n';
    int lenPlaintext = sizeOfPlaintext();
std::cout << "/* message */" << '\n';

    unsigned char plaintext[lenPlaintext];
    std::cout << "/* message */" << '\n';
    readInFile(plaintext);
    std::cout << "/* message */" << '\n';
std::cout << "plaintext :" << plaintext<< '\n';
    unsigned char cipherTextOut [lenPlaintext];
    unsigned char cipherTextIn [lenPlaintext];

    unsigned char ciphertext[lenPlaintext];

    unsigned char decryptedtext[lenPlaintext];


    encrypt (plaintext, lenPlaintext , key, iv, cipherTextOut);


    fileFill(cipherTextOut);

    encFileRead(cipherTextIn);


    decrypt(cipherTextIn, sizeOfPlaintext(), key, iv, decryptedtext);

    decryptedtext[lenPlaintext] = '\0';

    std::cout << "Decrypted :" << '\n'<<decryptedtext;

    return 0;
}
