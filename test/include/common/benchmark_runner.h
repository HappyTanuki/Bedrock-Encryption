#pragma once
// AES 모드 벤치마크 공통 러너. CBC(IV 있음) / ECB(IV 없음) 분기는 concept 처리.
//
// 사용 예:
//   return bedrock::test::RunAesBenchmark<bedrock::cipher::AES_CBC, 16>();
//   return bedrock::test::RunAesBenchmark<bedrock::cipher::AES_ECB, 32>();

#include <array>
#include <cstdint>
#include <ctime>
#include <iostream>

#include "common/kat_runner.h"  // HasIVCipher concept 재사용
#include "encryption/cipher/mode/aliases.h"
#include "encryption/cipher/mode/operation.h"

namespace bedrock::test {

template <typename Algorithm, std::size_t KeyBytes,
          std::uint64_t Iterations = 100000>
int RunAesBenchmark() {
  constexpr std::size_t kBlockBytes = 16;
  constexpr std::uint64_t kProcessedBytes = kBlockBytes * Iterations;

  std::array<std::uint8_t, kBlockBytes> buffer{};
  std::array<std::uint8_t, KeyBytes> key{};

  auto cipher = [&]() {
    if constexpr (HasIVCipher<Algorithm>) {
      std::array<std::uint8_t, kBlockBytes> iv{};
      return Algorithm{key, iv};
    } else {
      return Algorithm{key};
    }
  }();
  cipher << bedrock::cipher::op_mode::CipherMode::kEncrypt;

  auto start = std::clock();
  for (std::uint64_t i = 0; i < Iterations; ++i) {
    cipher.Process(buffer, buffer);
  }
  auto end = std::clock();

  const double elapsed = static_cast<double>(end - start) / CLOCKS_PER_SEC;
  std::cout << "Elapsed time: " << elapsed << " seconds" << '\n';
  std::cout << "bytes_processed: "
            << static_cast<double>(kProcessedBytes) / (1024 * 1024) << "mb"
            << '\n';
  std::cout << "throughput: "
            << static_cast<double>(kProcessedBytes) / elapsed / (1024 * 1024)
            << "mb/s" << '\n';
  return 0;
}

}  // namespace bedrock::test
