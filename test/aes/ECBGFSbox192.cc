#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/util/helper.h"
#include "encryption/util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::cipher::util::NISTTestVectorParser;

#define KEY_BIT 192
#define TEST_NAME "ECBGFSbox192"
#define ALGORITHM bedrock::cipher::AES_ECB
#define TESTDIRECTORY_PREFIX "./test/test_vector/"
#define TESTDIRECTORY "KAT_AES/"
#define TESTFILEEXT ".rsp"

int main() {
  std::vector<NISTTestVectorParser::NISTTestVariables> encrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherVector(
          TESTDIRECTORY_PREFIX TESTDIRECTORY TEST_NAME TESTFILEEXT,
          encrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kEncrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            encrypt_test_vectors.back().binary["error_msg"].data()),
        encrypt_test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }
  std::vector<NISTTestVectorParser::NISTTestVariables> decrypt_test_vectors;
  if (NISTTestVectorParser::ParseCipherVector(
          TESTDIRECTORY_PREFIX TESTDIRECTORY TEST_NAME TESTFILEEXT,
          decrypt_test_vectors,
          NISTTestVectorParser::VectorCategory::kDecrypt) !=
      NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            decrypt_test_vectors.back().binary["error_msg"].data()),
        decrypt_test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << TEST_NAME " Encryption:" << std::endl;
  for (const auto& item : encrypt_test_vectors) {
    std::array<std::byte, KEY_BIT / 8> key;

    std::copy(item.binary.at("KEY").begin(), item.binary.at("KEY").end(),
              key.begin());

    ALGORITHM cipher(key);
    std::vector<std::byte> input_block(16);
    std::vector<std::byte> output_block(16);
    std::vector<std::byte> expected_block(16);
    std::vector<std::byte> result;
    result.reserve(item.binary.at("CIPHERTEXT").size());

    cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

    std::cout << "KEY: "
              << bedrock::cipher::util::BytesToHexStr(item.binary.at("KEY"))
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.binary.at("PLAINTEXT"))
              << "\n";

    for (std::uint32_t i = 0;; i++) {
      if (i * 16 + 16 > item.binary.at("PLAINTEXT").size()) {
        break;
      }
      std::copy(i * 16 + item.binary.at("PLAINTEXT").begin(),
                i * 16 + item.binary.at("PLAINTEXT").begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary.at("CIPHERTEXT").begin(),
                i * 16 + item.binary.at("CIPHERTEXT").begin() + 16,
                expected_block.begin());

      cipher.Process(input_block, output_block);

      std::copy(output_block.begin(), output_block.end(),
                std::back_inserter(result));
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "PLAINTEXT block: "
                << bedrock::cipher::util::BytesToHexStr(input_block) << "\n";
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "expected block: "
                << bedrock::cipher::util::BytesToHexStr(expected_block) << "\n";
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "CIPHERTEXT block: "
                << bedrock::cipher::util::BytesToHexStr(output_block) << "\n";
      if (output_block != expected_block) {
        std::cout << "\t" << "Mismatch" << std::endl;
        return -1;
      }
    }

    std::cout << "EXPECTED: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.binary.at("CIPHERTEXT"))
              << "\n";
    std::cout << "CIPHERTEXT: " << bedrock::cipher::util::BytesToHexStr(result)
              << "\n";

    if (result != item.binary.at("CIPHERTEXT")) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << TEST_NAME " Decryption:" << std::endl;
  for (const auto& item : decrypt_test_vectors) {
    std::array<std::byte, KEY_BIT / 8> key;

    std::copy(item.binary.at("KEY").begin(), item.binary.at("KEY").end(),
              key.begin());

    ALGORITHM cipher(key);
    std::vector<std::byte> input_block(16);
    std::vector<std::byte> output_block(16);
    std::vector<std::byte> expected_block(16);
    std::vector<std::byte> result;
    result.reserve(item.binary.at("PLAINTEXT").size());

    cipher << bedrock::cipher::op_mode::CipherMode::Decrypt;

    std::cout << "KEY: "
              << bedrock::cipher::util::BytesToHexStr(item.binary.at("KEY"))
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.binary.at("CIPHERTEXT"))
              << "\n";

    for (std::uint32_t i = 0;; i++) {
      if (i * 16 + 16 > item.binary.at("CIPHERTEXT").size()) {
        break;
      }
      std::copy(i * 16 + item.binary.at("CIPHERTEXT").begin(),
                i * 16 + item.binary.at("CIPHERTEXT").begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary.at("PLAINTEXT").begin(),
                i * 16 + item.binary.at("PLAINTEXT").begin() + 16,
                expected_block.begin());

      cipher.Process(input_block, output_block);

      std::copy(output_block.begin(), output_block.end(),
                std::back_inserter(result));
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "CIPHERTEXT block: "
                << bedrock::cipher::util::BytesToHexStr(input_block) << "\n";
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "expected block: "
                << bedrock::cipher::util::BytesToHexStr(expected_block) << "\n";
      std::cout << "\t" << i + 1
                << bedrock::cipher::util::GetEnglishNumberSufix(i + 1) << " ";
      std::cout << "PLAINTEXT block: "
                << bedrock::cipher::util::BytesToHexStr(output_block) << "\n";
      if (output_block != expected_block) {
        std::cout << "\t" << "Mismatch" << std::endl;
        return -1;
      }
    }

    std::cout << "EXPECTED: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.binary.at("PLAINTEXT"))
              << "\n";
    std::cout << "PLAINTEXT: " << bedrock::cipher::util::BytesToHexStr(result)
              << "\n";

    if (result != item.binary.at("PLAINTEXT")) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}
