#include <ctime>
#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"

#define KEY_BIT 256
#define ALGORITHM bedrock::cipher::AES_CBC
#define ITERATIONS 10000000
#define PROCESSED_BYTES (16 * ITERATIONS)

int main() {
  std::array<std::uint8_t, 16> buffer = {};
  std::array<std::uint8_t, 32> key = {};
  std::array<std::uint8_t, 16> iv = {};

  double PROCESSED_KILOBYTES = static_cast<double>(PROCESSED_BYTES) / 1024.0;
  double PROCESSED_MEGABYTES = PROCESSED_KILOBYTES / 1024.0;

  ALGORITHM cipher(key, iv);

  auto start_time = std::clock();

  for (std::uint64_t i = 0; i < ITERATIONS; i++) {
    cipher.Process(buffer, buffer);
  }

  auto end_time = std::clock();

  double elapsed_time =
      static_cast<double>(end_time - start_time) / CLOCKS_PER_SEC;
  std::cout << "Elapsed time: " << elapsed_time << " seconds" << std::endl;
  std::cout << "bytes_processed: " << PROCESSED_MEGABYTES << "mb" << std::endl;
  std::cout << "throughput: " << PROCESSED_MEGABYTES / elapsed_time << "mb/s"
            << std::endl;

  return 0;
}
