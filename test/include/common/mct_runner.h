#pragma once
// NIST AES Monte Carlo Test 공통 러너.
// - CBC: stage 간 key 재계산(key = prev_key XOR mix_of_prev_results) + IV 사용
// - ECB: vector가 매 stage의 key를 직접 제공, IV 없음
// - subdir "aesmct": simple (마지막 결과만 비교)
// - subdir "aesmct_intermediate": complex (INTERMEDIATE COUNT마다 추가 비교)
//
// 사용 예:
//   return bedrock::test::RunMctTest<bedrock::cipher::AES_CBC, 16>(
//       "CBCMCT128", "aesmct", "simple");

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

#include "common/kat_runner.h"  // HasIVCipher concept 재사용
#include "common/nist_testvector_parser.h"
#include "encryption/cipher/mode/aliases.h"
#include "encryption/cipher/mode/operation.h"
#include "encryption/util/helper.h"

namespace bedrock::test {

namespace _mct {

namespace P = bedrock::util::NISTTestVectorParser;

inline bool LoadOrPrintError(const std::string& path, P::VectorCategory cat,
                             std::vector<P::NISTTestMonteStage>& out) {
  if (P::ParseCipherMonteVector(path, out, cat) !=
      P::ReturnStatusCode::kSuccess) {
    if (!out.empty()) {
      const auto& msg = out.back().variable.binary["error_msg"];
      std::string err(reinterpret_cast<const char*>(msg.data()), msg.size());
      std::cout << err << std::endl;
    }
    return false;
  }
  return true;
}

inline std::string StageOrdinal(std::uint32_t n) {
  if (n % 10 == 1 && n != 11) return "st";
  if (n % 10 == 2 && n != 12) return "nd";
  if (n % 10 == 3 && n != 13) return "rd";
  return "th";
}

// CBC stage-key mixing: NIST AES MCT spec.
template <std::size_t KeyBytes>
void MixCbcKey(std::array<std::uint8_t, KeyBytes>& key,
               const std::vector<P::NISTTestMonteStage>& vectors,
               std::uint32_t stage_idx,
               const std::vector<std::uint8_t>& prev_result,
               const std::vector<std::uint8_t>& prev_prev_result) {
  if (stage_idx == 0) {
    std::copy(vectors[0].variable.binary.at("KEY").begin(),
              vectors[0].variable.binary.at("KEY").end(), key.begin());
    return;
  }
  const auto& prev_key = vectors[stage_idx - 1].variable.binary.at("KEY");
  std::copy(prev_key.begin(), prev_key.end(), key.begin());

  if constexpr (KeyBytes == 16) {
    bedrock::util::XorInplace(key, prev_result);
  } else if constexpr (KeyBytes == 24) {
    std::vector<std::uint8_t> mix;
    mix.reserve(24);
    mix.insert(mix.end(), prev_prev_result.end() - 8, prev_prev_result.end());
    mix.insert(mix.end(), prev_result.begin(), prev_result.end());
    bedrock::util::XorInplace(key, mix);
  } else if constexpr (KeyBytes == 32) {
    std::vector<std::uint8_t> mix;
    mix.reserve(32);
    mix.insert(mix.end(), prev_prev_result.begin(), prev_prev_result.end());
    mix.insert(mix.end(), prev_result.begin(), prev_result.end());
    bedrock::util::XorInplace(key, mix);
  }
}

template <typename Algorithm, std::size_t KeyBytes>
bool RunDirection(const std::vector<P::NISTTestMonteStage>& vectors,
                  P::VectorCategory cat, const std::string& test_name,
                  const std::string& test_type) {
  namespace om = bedrock::cipher::op_mode;
  const bool encrypt = (cat == P::VectorCategory::kEncrypt);
  const char* in_label = encrypt ? "PLAINTEXT" : "CIPHERTEXT";
  const char* out_label = encrypt ? "CIPHERTEXT" : "PLAINTEXT";
  const std::string sample_key =
      std::string("Intermediate Vaue ") + out_label;  // typo "Vaue"은 NIST spec

  std::cout << test_name << " " << test_type << " "
            << (encrypt ? "Encryption" : "Decryption") << ":" << std::endl;

  std::vector<std::uint8_t> prev_result;
  std::vector<std::uint8_t> prev_prev_result;

  for (std::uint32_t stage_idx = 0; stage_idx < vectors.size(); ++stage_idx) {
    auto item = vectors[stage_idx];  // copy: samples 큐 pop을 위해

    // -- Key 결정 --
    std::array<std::uint8_t, KeyBytes> key{};
    if constexpr (HasIVCipher<Algorithm>) {
      MixCbcKey<KeyBytes>(key, vectors, stage_idx, prev_result,
                          prev_prev_result);
    } else {
      // ECB: vector의 KEY 그대로
      std::copy(item.variable.binary["KEY"].begin(),
                item.variable.binary["KEY"].end(), key.begin());
    }

    auto cipher = [&]() {
      if constexpr (HasIVCipher<Algorithm>) {
        std::array<std::uint8_t, 16> iv{};
        std::copy(item.variable.binary["IV"].begin(),
                  item.variable.binary["IV"].end(), iv.begin());
        return Algorithm{key, iv};
      } else {
        return Algorithm{key};
      }
    }();
    cipher << (encrypt ? om::CipherMode::Encrypt : om::CipherMode::Decrypt);

    const std::uint32_t stage_number = item.variable.integer["COUNT"];
    std::cout << stage_number + 1 << StageOrdinal(stage_number + 1)
              << " stage:\n";
    std::cout << "KEY: "
              << bedrock::util::BytesToHexStr(item.variable.binary["KEY"])
              << "\n";
    if constexpr (HasIVCipher<Algorithm>) {
      std::cout << "IV: "
                << bedrock::util::BytesToHexStr(item.variable.binary["IV"])
                << "\n";
    }
    std::cout << in_label << ": "
              << bedrock::util::BytesToHexStr(item.variable.binary[in_label])
              << "\n";

    // -- Inner loop 초기 입력 --
    std::vector<std::uint8_t> next_input;
    if constexpr (HasIVCipher<Algorithm>) {
      // CBC: 첫 j에선 plaintext/ciphertext, j>=1에선 IV/prev_result 처리
      next_input = item.variable.binary[in_label];
    } else {
      // ECB: prev_result에 plaintext/ciphertext 박고 시작
      next_input = item.variable.binary[in_label];
    }

    std::vector<std::uint8_t> result;
    for (std::uint32_t j = 0; j < 1000; ++j) {
      result.clear();
      result.reserve(next_input.size());
      for (std::size_t k = 0; k * 16 + 16 <= next_input.size(); ++k) {
        std::vector<std::uint8_t> input_block(next_input.begin() + k * 16,
                                              next_input.begin() + k * 16 + 16);
        std::vector<std::uint8_t> output_block(16);
        cipher.Process(input_block, output_block);
        std::copy(output_block.begin(), output_block.end(),
                  std::back_inserter(result));
      }

      // INTERMEDIATE COUNT 비교 (complex만 사용)
      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == j) {
        auto sample = item.samples.front();
        item.samples.pop();
        std::cout << "\tINTERMEDIATE COUNT: " << j << "\n";
        std::cout << "\tIntermediate expected " << out_label << ": "
                  << bedrock::util::BytesToHexStr(
                         sample.variable.binary[sample_key])
                  << "\n";
        std::cout << "\tIntermediate Vaue " << out_label << ": "
                  << bedrock::util::BytesToHexStr(result) << "\n";
        if (result != sample.variable.binary[sample_key]) {
          std::cout << "\tIntermediate Vaue Mismatch" << std::endl;
          return false;
        }
      }

      // 다음 iter 입력 갱신
      if constexpr (HasIVCipher<Algorithm>) {
        // CBC: j==0이면 next_input = IV, 아니면 prev_result
        if (j == 0) {
          next_input = item.variable.binary["IV"];
        } else {
          next_input = prev_result;
        }
      } else {
        // ECB: prev_result 그대로
        next_input = result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }

    std::cout << "EXPECTED " << out_label << ": "
              << bedrock::util::BytesToHexStr(item.variable.binary[out_label])
              << "\n";
    std::cout << out_label << ": " << bedrock::util::BytesToHexStr(prev_result)
              << "\n";
    if (prev_result != item.variable.binary[out_label]) {
      std::cout << "Mismatch" << std::endl;
      return false;
    }
  }
  return true;
}

}  // namespace _mct

template <typename Algorithm, std::size_t KeyBytes>
int RunMctTest(const std::string& test_name, const std::string& subdir,
               const std::string& test_type) {
  namespace P = bedrock::util::NISTTestVectorParser;
  // aesmct/는 .rsp, aesmct_intermediate/는 .txt 사용 (NIST 배포 그대로).
  const std::string ext = (subdir == "aesmct_intermediate") ? ".txt" : ".rsp";
  const std::string path = "../test_vector/" + subdir + "/" + test_name + ext;

  std::vector<P::NISTTestMonteStage> enc;
  std::vector<P::NISTTestMonteStage> dec;
  if (!_mct::LoadOrPrintError(path, P::VectorCategory::kEncrypt, enc))
    return -1;
  if (!_mct::LoadOrPrintError(path, P::VectorCategory::kDecrypt, dec))
    return -1;

  if (!_mct::RunDirection<Algorithm, KeyBytes>(enc, P::VectorCategory::kEncrypt,
                                               test_name, test_type))
    return -1;
  if (!_mct::RunDirection<Algorithm, KeyBytes>(dec, P::VectorCategory::kDecrypt,
                                               test_name, test_type))
    return -1;
  return 0;
}

}  // namespace bedrock::test
