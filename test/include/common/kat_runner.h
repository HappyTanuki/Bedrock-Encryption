#pragma once
// NIST AES KAT/MMT 테스트 공통 러너.
// CBC(IV 있음) / ECB(IV 없음) 양쪽을 concept으로 분기.
//
// 사용 예:
//   return bedrock::test::RunKatTest<bedrock::cipher::AES_CBC,
//   16>("CBCGFSbox128"); return
//   bedrock::test::RunKatTest<bedrock::cipher::AES_ECB, 32>("ECBMMT256",
//   "aesmmt");

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "common/nist_testvector_parser.h"
#include "encryption/cipher/mode/aliases.h"
#include "encryption/cipher/mode/operation.h"
#include "encryption/util/helper.h"

namespace bedrock::test {

template <typename Algo>
concept HasIVCipher =
    requires(std::array<std::uint8_t, 16> k, std::array<std::uint8_t, 16> iv) {
      Algo(k, iv);
    };

namespace _kat {

namespace P = bedrock::util::NISTTestVectorParser;

inline bool LoadOrPrintError(const std::string& path, P::VectorCategory cat,
                             std::vector<P::NISTTestVariables>& out) {
  if (P::ParseCipherVector(path, out, cat) != P::ReturnStatusCode::kSuccess) {
    if (!out.empty()) {
      const auto& msg = out.back().binary["error_msg"];
      std::string err(reinterpret_cast<const char*>(msg.data()), msg.size());
      std::cout << err << std::endl;
    }
    return false;
  }
  return true;
}

template <typename Algorithm, std::size_t KeyBytes>
auto MakeCipher(const P::NISTTestVariables& item) {
  std::array<std::uint8_t, KeyBytes> key{};
  std::copy(item.binary.at("KEY").begin(), item.binary.at("KEY").end(),
            key.begin());
  if constexpr (HasIVCipher<Algorithm>) {
    std::array<std::uint8_t, 16> iv{};
    std::copy(item.binary.at("IV").begin(), item.binary.at("IV").end(),
              iv.begin());
    return Algorithm{key, iv};
  } else {
    return Algorithm{key};
  }
}

template <typename Algorithm>
bool ProcessOne(const P::NISTTestVariables& item, P::VectorCategory cat,
                Algorithm& cipher) {
  namespace om = bedrock::cipher::op_mode;
  const bool encrypt = (cat == P::VectorCategory::kEncrypt);
  const char* in_label = encrypt ? "PLAINTEXT" : "CIPHERTEXT";
  const char* out_label = encrypt ? "CIPHERTEXT" : "PLAINTEXT";

  cipher << (encrypt ? om::CipherMode::kEncrypt : om::CipherMode::kDecrypt);

  const auto& in_bytes = item.binary.at(in_label);
  const auto& exp_bytes = item.binary.at(out_label);

  std::cout << "KEY: " << bedrock::util::BytesToHexStr(item.binary.at("KEY"))
            << "\n";
  if constexpr (HasIVCipher<Algorithm>) {
    std::cout << "IV: " << bedrock::util::BytesToHexStr(item.binary.at("IV"))
              << "\n";
  }
  std::cout << in_label << ": " << bedrock::util::BytesToHexStr(in_bytes)
            << "\n";

  std::vector<std::uint8_t> result;
  result.reserve(exp_bytes.size());

  for (std::uint32_t i = 0; (i + 1) * 16 <= in_bytes.size(); ++i) {
    std::vector<std::uint8_t> input_block(in_bytes.begin() + i * 16,
                                          in_bytes.begin() + i * 16 + 16);
    std::vector<std::uint8_t> expected_block(exp_bytes.begin() + i * 16,
                                             exp_bytes.begin() + i * 16 + 16);
    std::vector<std::uint8_t> output_block(16);

    cipher.Process(input_block, output_block);
    std::copy(output_block.begin(), output_block.end(),
              std::back_inserter(result));

    auto suffix = bedrock::util::GetEnglishNumberSufix(i + 1);
    std::cout << "\t" << i + 1 << suffix << " " << in_label
              << " block: " << bedrock::util::BytesToHexStr(input_block)
              << "\n";
    std::cout << "\t" << i + 1 << suffix << " expected block: "
              << bedrock::util::BytesToHexStr(expected_block) << "\n";
    std::cout << "\t" << i + 1 << suffix << " " << out_label
              << " block: " << bedrock::util::BytesToHexStr(output_block)
              << "\n";

    if (output_block != expected_block) {
      std::cout << "\tMismatch" << std::endl;
      return false;
    }
  }

  std::cout << "EXPECTED: " << bedrock::util::BytesToHexStr(exp_bytes) << "\n";
  std::cout << out_label << ": " << bedrock::util::BytesToHexStr(result)
            << "\n";

  if (result != exp_bytes) {
    std::cout << "Mismatch" << std::endl;
    return false;
  }
  return true;
}

template <typename Algorithm, std::size_t KeyBytes>
bool RunDirection(const std::vector<P::NISTTestVariables>& vectors,
                  P::VectorCategory cat, const std::string& test_name) {
  std::cout << test_name << " "
            << (cat == P::VectorCategory::kEncrypt ? "Encryption"
                                                   : "Decryption")
            << ":" << std::endl;
  for (const auto& item : vectors) {
    auto cipher = MakeCipher<Algorithm, KeyBytes>(item);
    if (!ProcessOne(item, cat, cipher)) return false;
  }
  return true;
}

}  // namespace _kat

template <typename Algorithm, std::size_t KeyBytes>
int RunKatTest(const std::string& test_name,
               const std::string& subdir = "KAT_AES") {
  namespace P = bedrock::util::NISTTestVectorParser;
  const std::string path =
      "../test_vector/" + subdir + "/" + test_name + ".rsp";

  std::vector<P::NISTTestVariables> enc;
  std::vector<P::NISTTestVariables> dec;
  if (!_kat::LoadOrPrintError(path, P::VectorCategory::kEncrypt, enc))
    return -1;
  if (!_kat::LoadOrPrintError(path, P::VectorCategory::kDecrypt, dec))
    return -1;

  if (!_kat::RunDirection<Algorithm, KeyBytes>(enc, P::VectorCategory::kEncrypt,
                                               test_name))
    return -1;
  if (!_kat::RunDirection<Algorithm, KeyBytes>(dec, P::VectorCategory::kDecrypt,
                                               test_name))
    return -1;
  return 0;
}

}  // namespace bedrock::test
