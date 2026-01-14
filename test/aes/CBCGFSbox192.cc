#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/util/helper.h"
#include "encryption/util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::cipher::util::NISTTestVectorParser;

#define KEY_BIT 192
#define ALGORITHM bedrock::cipher::AES_CBC
#define TESTDIRECTORY_PREFIX "./test/test_vector/"
#define TESTDIRECTORY "KAT_AES/"
#define TEST_NAME "CBCGFSbox192"
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
  for (auto item : encrypt_test_vectors) {
    std::array<std::byte, KEY_BIT / 8> key;
    std::array<std::byte, 16> IV;

    std::copy(item.binary["KEY"].begin(), item.binary["KEY"].end(),
              key.begin());
    std::copy(item.binary["IV"].begin(), item.binary["IV"].end(), IV.begin());

    ALGORITHM cipher(key, IV);
    std::vector<std::byte> input_block(16);
    std::vector<std::byte> output_block(16);
    std::vector<std::byte> expected_block(16);
    std::vector<std::byte> result;
    result.reserve(item.binary["CIPHERTEXT"].size());

    cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

    std::cout << "KEY: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["KEY"])
              << "\n";
    std::cout << "IV: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["IV"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["PLAINTEXT"])
              << "\n";

    for (std::uint32_t i = 0;; i++) {
      if (i * 16 + 16 > item.binary["PLAINTEXT"].size()) {
        break;
      }
      std::copy(i * 16 + item.binary["PLAINTEXT"].begin(),
                i * 16 + item.binary["PLAINTEXT"].begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary["CIPHERTEXT"].begin(),
                i * 16 + item.binary["CIPHERTEXT"].begin() + 16,
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
              << bedrock::cipher::util::BytesToHexStr(item.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: " << bedrock::cipher::util::BytesToHexStr(result)
              << "\n";

    if (result != item.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << TEST_NAME " Decryption:" << std::endl;
  for (auto item : decrypt_test_vectors) {
    std::array<std::byte, KEY_BIT / 8> key;
    std::array<std::byte, 16> IV;

    std::copy(item.binary["KEY"].begin(), item.binary["KEY"].end(),
              key.begin());
    std::copy(item.binary["IV"].begin(), item.binary["IV"].end(), IV.begin());

    ALGORITHM cipher(key, IV);
    std::vector<std::byte> input_block(16);
    std::vector<std::byte> output_block(16);
    std::vector<std::byte> expected_block(16);
    std::vector<std::byte> result;
    result.reserve(item.binary["PLAINTEXT"].size());

    cipher << bedrock::cipher::op_mode::CipherMode::Decrypt;

    std::cout << "KEY: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["KEY"])
              << "\n";
    std::cout << "IV: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["IV"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::cipher::util::BytesToHexStr(item.binary["CIPHERTEXT"])
              << "\n";

    for (std::uint32_t i = 0;; i++) {
      if (i * 16 + 16 > item.binary["CIPHERTEXT"].size()) {
        break;
      }
      std::copy(i * 16 + item.binary["CIPHERTEXT"].begin(),
                i * 16 + item.binary["CIPHERTEXT"].begin() + 16,
                input_block.begin());
      std::copy(i * 16 + item.binary["PLAINTEXT"].begin(),
                i * 16 + item.binary["PLAINTEXT"].begin() + 16,
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
              << bedrock::cipher::util::BytesToHexStr(item.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: " << bedrock::cipher::util::BytesToHexStr(result)
              << "\n";

    if (result != item.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}
