#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <array>
#include <cstring>
#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"

#define ALGORITHM bedrock::cipher::AES_ECB

int main(int argc, char* argv[]) {
  std::array<std::uint8_t, 16> buffer = {};
  std::array<std::uint8_t, 32> key = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                      0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                                      0xAA, 0xAA, 0xAA, 0xAA};
  std::array<std::uint8_t, 16> target = {};

  if (argv != nullptr) {
  }

  ::EVP_MD* md = ::EVP_MD_fetch(NULL, "SHA2-256", NULL);

  ALGORITHM cipher(key);
  cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

  std::cout << "Program is now running..." << std::endl;

  std::size_t i = 0;
  while (++i) {
    cipher.Process(buffer, buffer);

    if (buffer == target) {
      std::cout << "i: " << i << std::endl;
      break;
    }

    if (argc < 2) {
      break;
    }

    buffer[i % 16] ^= static_cast<uint8_t>(i);
  }

  ::EVP_MD_free(md);

  return 0;
}
