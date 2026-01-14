#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/util/helper.h"
#include "encryption/util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::cipher::util::NISTTestVectorParser;

#define TEST_TYPE "simple"

#define KEY_BIT 256
#define ALGORITHM bedrock::cipher::AES_CBC
#define TESTDIRECTORY_PREFIX "./test/test_vector/"
#define TESTDIRECTORY "aesmct/"
#define TEST_NAME "CBCMCT256"
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

  std::vector<std::byte> prev_result;
  std::vector<std::byte> prev_prev_result;

  std::cout << TEST_NAME " " TEST_TYPE " Encryption:" << std::endl;
  for (std::uint32_t i = 0; i < encrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = encrypt_test_vectors[i];
    std::array<std::byte, KEY_BIT / 8> key;
    if (i == 0) {
      std::copy(item.variable.binary["KEY"].begin(),
                item.variable.binary["KEY"].end(), key.begin());
    } else if (KEY_BIT == 128) {
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], prev_result);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    } else if (KEY_BIT == 192) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    } else if (KEY_BIT == 256) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          encrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    }
    std::array<std::byte, 16> IV;
    std::copy(item.variable.binary["IV"].begin(),
              item.variable.binary["IV"].end(), IV.begin());

    ALGORITHM cipher(key, IV);
    cipher << bedrock::cipher::op_mode::CipherMode::Encrypt;

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
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["KEY"])
              << " (" << std::to_integer<int>(item.variable.binary["KEY"][0])
              << ", " << std::to_integer<int>(item.variable.binary["KEY"][1])
              << " ... "
              << std::to_integer<int>(item.variable.binary["KEY"][14]) << ", "
              << std::to_integer<int>(item.variable.binary["KEY"][15]) << ") "
              << "\n";
    std::cout << "IV: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["IV"])
              << " (" << std::to_integer<int>(item.variable.binary["IV"][0])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][1])
              << " ... " << std::to_integer<int>(item.variable.binary["IV"][14])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][15])
              << ") "
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["PLAINTEXT"])
              << " ("
              << std::to_integer<int>(item.variable.binary["PLAINTEXT"][0])
              << ", "
              << std::to_integer<int>(item.variable.binary["PLAINTEXT"][1])
              << " ... "
              << std::to_integer<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 2])
              << ", "
              << std::to_integer<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::byte> next_input;
    next_input.resize(item.variable.binary["PLAINTEXT"].size());
    std::copy(item.variable.binary["PLAINTEXT"].begin(),
              item.variable.binary["PLAINTEXT"].end(), next_input.begin());

    for (std::uint32_t j = 0; j < 1000; j++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (std::uint32_t k = 0; k * 16 + 16 <= next_input.size(); k++) {
        std::vector<std::byte> input_block(16);
        std::copy(k * 16 + next_input.begin(), k * 16 + next_input.begin() + 16,
                  input_block.begin());
        std::vector<std::byte> output_block(16);

        cipher.Process(input_block, output_block);

        std::copy(output_block.begin(), output_block.end(),
                  std::back_inserter(result));
      }

      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == j) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << j << "\n";
        std::cout
            << "\t" << "Intermediate expected CIPHERTEXT: "
            << bedrock::cipher::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"])
            << " ("
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][0])
            << ", "
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][1])
            << " ... "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               2])
            << ", "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue CIPHERTEXT: "
                  << bedrock::cipher::util::BytesToHexStr(result) << " ("
                  << std::to_integer<int>(result[0]) << ", "
                  << std::to_integer<int>(result[1]) << " ... "
                  << std::to_integer<int>(result[result.size() - 2]) << ", "
                  << std::to_integer<int>(result[result.size() - 1]) << ") "
                  << "\n";

        if (result != sample.variable.binary["Intermediate Vaue CIPHERTEXT"]) {
          std::cout << "\t" << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }

      if (j == 0) {
        next_input = item.variable.binary["IV"];
      } else {
        next_input = prev_result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }

    std::cout << "EXPECTED CIPHERTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::cipher::util::BytesToHexStr(prev_result) << "\n";

    if (prev_result != item.variable.binary["CIPHERTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }
  std::cout << TEST_NAME " " TEST_TYPE " Decryption:" << std::endl;
  for (std::uint32_t i = 0; i < decrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = decrypt_test_vectors[i];
    std::array<std::byte, KEY_BIT / 8> key;
    if (i == 0) {
      std::copy(item.variable.binary["KEY"].begin(),
                item.variable.binary["KEY"].end(), key.begin());
    } else if (KEY_BIT == 128) {
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], prev_result);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    } else if (KEY_BIT == 192) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    } else if (KEY_BIT == 256) {
      std::vector<std::byte> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::vector<std::byte> temp_key = bedrock::cipher::util::XorBytes(
          decrypt_test_vectors[i - 1].variable.binary["KEY"], temp_t);
      std::copy(temp_key.begin(), temp_key.end(), key.begin());
    }
    std::array<std::byte, 16> IV;
    std::copy(item.variable.binary["IV"].begin(),
              item.variable.binary["IV"].end(), IV.begin());

    ALGORITHM cipher(key, IV);
    cipher << bedrock::cipher::op_mode::CipherMode::Decrypt;

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
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["KEY"])
              << " (" << std::to_integer<int>(item.variable.binary["KEY"][0])
              << ", " << std::to_integer<int>(item.variable.binary["KEY"][1])
              << " ... "
              << std::to_integer<int>(item.variable.binary["KEY"][14]) << ", "
              << std::to_integer<int>(item.variable.binary["KEY"][15]) << ") "
              << "\n";
    std::cout << "IV: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["IV"])
              << " (" << std::to_integer<int>(item.variable.binary["IV"][0])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][1])
              << " ... " << std::to_integer<int>(item.variable.binary["IV"][14])
              << ", " << std::to_integer<int>(item.variable.binary["IV"][15])
              << ") "
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << " ("
              << std::to_integer<int>(item.variable.binary["CIPHERTEXT"][0])
              << ", "
              << std::to_integer<int>(item.variable.binary["CIPHERTEXT"][1])
              << " ... "
              << std::to_integer<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 2])
              << ", "
              << std::to_integer<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::byte> next_input;
    next_input.resize(item.variable.binary["CIPHERTEXT"].size());
    std::copy(item.variable.binary["CIPHERTEXT"].begin(),
              item.variable.binary["CIPHERTEXT"].end(), next_input.begin());

    for (std::uint32_t j = 0; j < 1000; j++) {
      std::vector<std::byte> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (std::uint32_t k = 0; k * 16 + 16 <= next_input.size(); k++) {
        std::vector<std::byte> input_block(16);
        std::copy(k * 16 + next_input.begin(), k * 16 + next_input.begin() + 16,
                  input_block.begin());
        std::vector<std::byte> output_block(16);

        cipher.Process(input_block, output_block);

        std::copy(output_block.begin(), output_block.end(),
                  std::back_inserter(result));
      }

      if (!item.samples.empty() &&
          item.samples.front().variable.integer["INTERMEDIATE COUNT"] == j) {
        NISTTestVectorParser::NISTTestMonteSample sample = item.samples.front();
        item.samples.pop();

        std::cout << "\t" << "INTERMEDIATE COUNT: " << j << "\n";
        std::cout
            << "\t" << "Intermediate expected PLAINTEXT: "
            << bedrock::cipher::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"])
            << " ("
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][0])
            << ", "
            << std::to_integer<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][1])
            << " ... "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               2])
            << ", "
            << std::to_integer<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue PLAINTEXT: "
                  << bedrock::cipher::util::BytesToHexStr(result) << " ("
                  << std::to_integer<int>(result[0]) << ", "
                  << std::to_integer<int>(result[1]) << " ... "
                  << std::to_integer<int>(result[result.size() - 2]) << ", "
                  << std::to_integer<int>(result[result.size() - 1]) << ") "
                  << "\n";

        if (result != sample.variable.binary["Intermediate Vaue PLAINTEXT"]) {
          std::cout << "\t" << "Intermediate Vaue Mismatch" << std::endl;
          return -1;
        }
      }

      if (j == 0) {
        next_input = item.variable.binary["IV"];
      } else {
        next_input = prev_result;
      }
      prev_prev_result = prev_result;
      prev_result = result;
    }

    std::cout << "EXPECTED PLAINTEXT: "
              << bedrock::cipher::util::BytesToHexStr(
                     item.variable.binary["PLAINTEXT"])
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::cipher::util::BytesToHexStr(prev_result) << "\n";

    if (prev_result != item.variable.binary["PLAINTEXT"]) {
      std::cout << "Mismatch" << std::endl;
      return -1;
    }
  }

  return 0;
}
