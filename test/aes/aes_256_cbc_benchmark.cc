#include <ctime>
#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/block_cipher/mode/operation.h"

#define KEY_BIT 256
#define ALGORITHM bedrock::cipher::AES_CBC
#define ITERATIONS 10000000
#define PROCESSED_BYTES (16 * ITERATIONS)

int main() {
  std::array<std::uint8_t, 16> buffer = {};
  std::array<std::uint8_t, KEY_BIT / 8> key = {};
  std::array<std::uint8_t, 16> iv = {};

  ALGORITHM cipher(key, iv);
  cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

  auto start_time = std::clock();

  for (std::uint64_t i = 0; i < ITERATIONS; i++) {
    cipher.Process(buffer, buffer);
  }

  auto end_time = std::clock();

  double elapsed_time =
      static_cast<double>(end_time - start_time) / CLOCKS_PER_SEC;
  std::cout << "Elapsed time: " << elapsed_time << " seconds" << std::endl;
  std::cout << "bytes_processed: "
            << static_cast<double>(PROCESSED_BYTES) / (1024 * 1024) << "mb"
            << std::endl;
  std::cout << "throughput: "
            << static_cast<double>(PROCESSED_BYTES) / elapsed_time /
                   (1024 * 1024)
            << "mb/s" << std::endl;

  return 0;
}
