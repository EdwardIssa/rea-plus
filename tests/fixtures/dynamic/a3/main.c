#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "blob.h"
static const unsigned char seed[] = { 97, 51, 45, 107, 100, 102, 45, 115, 101, 101, 100 };
static void load_config(void) {
  unsigned char digest[32];
  unsigned char iv[16] = { 0 };
  unsigned char out[128];
  int outLen = 0, tmpLen = 0;
  EVP_CIPHER_CTX *ctx;
  SHA256(seed, sizeof(seed), digest);
  ctx = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), 0, digest, iv);
  EVP_DecryptUpdate(ctx, out, &outLen, BLOB, (int)BLOB_LEN);
  EVP_DecryptFinal_ex(ctx, out + outLen, &tmpLen);
  outLen += tmpLen;
  out[outLen] = '\0';
  EVP_CIPHER_CTX_free(ctx);
  puts("MARK:load_config");
  puts((const char *)out);
}
int main(void) { puts("MARK:main"); load_config(); return 0; }
