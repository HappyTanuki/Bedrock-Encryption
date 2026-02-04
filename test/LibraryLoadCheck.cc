#include "encryption/block_cipher/mode/aliases.h"
#include <array>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>

#define ALGORITHM bedrock::cipher::AES_ECB

int main() {
  std::array<std::uint8_t, 16> buffer = {};
  std::array<std::uint8_t, 16> key = {};

  EVP_MD *md = EVP_MD_fetch(NULL, "SHA2-256", NULL);

  ALGORITHM cipher(key);
  cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

  while (true) {
    cipher.Process(buffer, buffer);
  }

  EVP_MD_free(md);

  return 0;
}
