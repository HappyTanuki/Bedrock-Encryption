#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/util/helper.h"
#include "encryption/util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::util::NISTTestVectorParser;

#define TEST_TYPE "simple"

#define KEY_BIT 128
#define ALGORITHM bedrock::cipher::AES_ECB
#define TESTDIRECTORY_PREFIX "./test/test_vector/"
#define TESTDIRECTORY "aesmct/"
#define TEST_NAME "ECBMCT128"
#define TESTFILEEXT ".rsp"

int main() {
  std::vector<NISTTestVectorParser::NISTTestMonteStage> encrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherMonteVector(
          TESTDIRECTORY_PREFIX TESTDIRECTORY TEST_NAME TESTFILEEXT,
          encrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kEncrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            encrypt_test_vectors.back().variable.binary["error_msg"].data()),
        encrypt_test_vectors.back().variable.binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }
  std::vector<NISTTestVectorParser::NISTTestMonteStage> decrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherMonteVector(
          TESTDIRECTORY_PREFIX TESTDIRECTORY TEST_NAME TESTFILEEXT,
          decrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kDecrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            decrypt_test_vectors.back().variable.binary["error_msg"].data()),
        decrypt_test_vectors.back().variable.binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::vector<std::uint8_t> input_block;
  std::vector<std::uint8_t> output_block;
  input_block.resize(16);
  output_block.resize(16);

  std::cout << TEST_NAME " " TEST_TYPE " Encryption:" << std::endl;
  for (auto item : encrypt_test_vectors) {
    std::vector<std::uint8_t> prev_result;
    prev_result.resize(item.variable.binary["PLAINTEXT"].size());
    std::array<std::uint8_t, KEY_BIT / 8> key;
    std::copy(item.variable.binary["KEY"].begin(),
              item.variable.binary["KEY"].end(), key.begin());

    ALGORITHM cipher(key);
    cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

    std::copy(item.variable.binary["PLAINTEXT"].begin(),
              item.variable.binary["PLAINTEXT"].end(), prev_result.begin());

    std::uint32_t stage_number = item.variable.integer["COUNT"];

    std::cout << stage_number + 1;
    if ((stage_number + 1) % 10 == 1 && (stage_number + 1) != 11) {
      std::cout << "st ";
    } else if ((stage_number + 1) % 10 == 2 && (stage_number + 1) != 12) {
      std::cout << "nd ";
    } else if ((stage_number + 1) % 10 == 3 && (stage_number + 1) != 13) {
      std::cout << "rd ";
    } else {
      std::cout << "th ";
    }
    std::cout << "stage: " << "\n";

    std::cout << "KEY: "
              << bedrock::util::BytesToHexStr(item.variable.binary["KEY"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::util::BytesToHexStr(item.variable.binary["PLAINTEXT"])
              << "\n";

    for (std::uint32_t i = 0; i < 1000; i++) {
      std::vector<std::uint8_t> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());
      for (std::uint32_t j = 0;; j++) {
        if (j * 16 + 16 > prev_result.size()) {
          break;
        }
        std::copy(j * 16 + prev_result.begin(),
                  j * 16 + prev_result.begin() + 16, input_block.begin());

        cipher.Process(input_block, output_block);

        std::copy(output_block.begin(), output_block.end(),
                  std::back_inserter(result));
      }
      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == i) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << i << "\n";
        std::cout << "\t" << "Intermediate expected CIPHERTEXT: "
                  << bedrock::util::BytesToHexStr(
                         sample.variable.binary["Intermediate Vaue CIPHERTEXT"])
                  << "\n";
        std::cout << "\t" << "Intermediate Vaue CIPHERTEXT: "
                  << bedrock::util::BytesToHexStr(result) << "\n";

        if (result != sample.variable.binary["Intermediate Vaue CIPHERTEXT"]) {
          std::cout << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }
      prev_result = result;
    }

    std::cout << "EXPECTED CIPHERTEXT: "
              << bedrock::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: " << bedrock::util::BytesToHexStr(prev_result)
              << "\n";

    if (prev_result != item.variable.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << TEST_NAME " " TEST_TYPE " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::vector<std::uint8_t> prev_result;
    prev_result.resize(item.variable.binary["CIPHERTEXT"].size());
    std::array<std::uint8_t, KEY_BIT / 8> key;
    std::copy(item.variable.binary["KEY"].begin(),
              item.variable.binary["KEY"].end(), key.begin());

    ALGORITHM cipher(key);
    cipher << bedrock::cipher::op_mode::CipherMode::Decrypt;

    std::copy(item.variable.binary["CIPHERTEXT"].begin(),
              item.variable.binary["CIPHERTEXT"].end(), prev_result.begin());

    std::uint32_t stage_number = item.variable.integer["COUNT"];

    std::cout << stage_number + 1;
    if ((stage_number + 1) % 10 == 1 && (stage_number + 1) != 11) {
      std::cout << "st ";
    } else if ((stage_number + 1) % 10 == 2 && (stage_number + 1) != 12) {
      std::cout << "nd ";
    } else if ((stage_number + 1) % 10 == 3 && (stage_number + 1) != 13) {
      std::cout << "rd ";
    } else {
      std::cout << "th ";
    }
    std::cout << "stage: " << "\n";

    std::cout << "KEY: "
              << bedrock::util::BytesToHexStr(item.variable.binary["KEY"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";

    for (std::uint32_t i = 0; i < 1000; i++) {
      std::vector<std::uint8_t> result;
      result.reserve(item.variable.binary["CIPHERTEXT"].size());
      for (std::uint32_t j = 0;; j++) {
        if (j * 16 + 16 > prev_result.size()) {
          break;
        }
        std::copy(j * 16 + prev_result.begin(),
                  j * 16 + prev_result.begin() + 16, input_block.begin());

        cipher.Process(input_block, output_block);

        std::copy(output_block.begin(), output_block.end(),
                  std::back_inserter(result));
      }
      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == i) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << i << "\n";
        std::cout << "\t" << "Intermediate expected PLAINTEXT: "
                  << bedrock::util::BytesToHexStr(
                         sample.variable.binary["Intermediate Vaue PLAINTEXT"])
                  << "\n";
        std::cout << "\t" << "Intermediate Vaue PLAINTEXT: "
                  << bedrock::util::BytesToHexStr(result) << "\n";

        if (result != sample.variable.binary["Intermediate Vaue PLAINTEXT"]) {
          std::cout << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }
      prev_result = result;
    }

    std::cout << "EXPECTED PLAINTEXT: "
              << bedrock::util::BytesToHexStr(item.variable.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: " << bedrock::util::BytesToHexStr(prev_result)
              << "\n";

    if (prev_result != item.variable.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}
