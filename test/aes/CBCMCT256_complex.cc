#include <iostream>

#include "encryption/block_cipher/mode/aliases.h"
#include "encryption/util/helper.h"
#include "encryption/util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::util::NISTTestVectorParser;

#define TEST_TYPE "complex"

#define KEY_BIT 256
#define ALGORITHM bedrock::cipher::AES_CBC
#define TESTDIRECTORY_PREFIX "./test/test_vector/"
#define TESTDIRECTORY "aesmct_intermediate/"
#define TEST_NAME "CBCMCT256"
#define TESTFILEEXT ".txt"

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

  std::vector<std::uint8_t> prev_result;
  std::vector<std::uint8_t> prev_prev_result;

  std::cout << TEST_NAME " " TEST_TYPE " Encryption:" << std::endl;
  for (std::uint32_t i = 0; i < encrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = encrypt_test_vectors[i];
    std::array<std::uint8_t, KEY_BIT / 8> key;
    if (i == 0) {
      std::copy(item.variable.binary["KEY"].begin(),
                item.variable.binary["KEY"].end(), key.begin());
    } else if (KEY_BIT == 128) {
      std::copy(encrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                encrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, prev_result);
    } else if (KEY_BIT == 192) {
      std::vector<std::uint8_t> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::copy(encrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                encrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, temp_t);
    } else if (KEY_BIT == 256) {
      std::vector<std::uint8_t> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::copy(encrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                encrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, temp_t);
    }
    std::array<std::uint8_t, 16> IV;
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
              << bedrock::util::BytesToHexStr(item.variable.binary["KEY"])
              << " (" << static_cast<int>(item.variable.binary["KEY"][0])
              << ", " << static_cast<int>(item.variable.binary["KEY"][1])
              << " ... " << static_cast<int>(item.variable.binary["KEY"][14])
              << ", " << static_cast<int>(item.variable.binary["KEY"][15])
              << ") "
              << "\n";
    std::cout << "IV: "
              << bedrock::util::BytesToHexStr(item.variable.binary["IV"])
              << " (" << static_cast<int>(item.variable.binary["IV"][0]) << ", "
              << static_cast<int>(item.variable.binary["IV"][1]) << " ... "
              << static_cast<int>(item.variable.binary["IV"][14]) << ", "
              << static_cast<int>(item.variable.binary["IV"][15]) << ") "
              << "\n";
    std::cout << "PLAINTEXT: "
              << bedrock::util::BytesToHexStr(item.variable.binary["PLAINTEXT"])
              << " (" << static_cast<int>(item.variable.binary["PLAINTEXT"][0])
              << ", " << static_cast<int>(item.variable.binary["PLAINTEXT"][1])
              << " ... "
              << static_cast<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 2])
              << ", "
              << static_cast<int>(
                     item.variable
                         .binary["PLAINTEXT"]
                                [item.variable.binary["PLAINTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::uint8_t> next_input;
    next_input.resize(item.variable.binary["PLAINTEXT"].size());
    std::copy(item.variable.binary["PLAINTEXT"].begin(),
              item.variable.binary["PLAINTEXT"].end(), next_input.begin());

    for (std::uint32_t j = 0; j < 1000; j++) {
      std::vector<std::uint8_t> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (std::uint32_t k = 0; k * 16 + 16 <= next_input.size(); k++) {
        std::vector<std::uint8_t> input_block(16);
        std::copy(k * 16 + next_input.begin(), k * 16 + next_input.begin() + 16,
                  input_block.begin());
        std::vector<std::uint8_t> output_block(16);

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
            << bedrock::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"])
            << " ("
            << static_cast<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][0])
            << ", "
            << static_cast<int>(
                   sample.variable.binary["Intermediate Vaue CIPHERTEXT"][1])
            << " ... "
            << static_cast<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               2])
            << ", "
            << static_cast<int>(
                   sample.variable
                       .binary["Intermediate Vaue CIPHERTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue CIPHERTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue CIPHERTEXT: "
                  << bedrock::util::BytesToHexStr(result) << " (" << result[0]
                  << ", " << result[1] << " ... " << result[result.size() - 2]
                  << ", " << result[result.size() - 1] << " "
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
  for (std::uint32_t i = 0; i < decrypt_test_vectors.size(); i++) {
    NISTTestVectorParser::NISTTestMonteStage item = decrypt_test_vectors[i];
    std::array<std::uint8_t, KEY_BIT / 8> key;
    if (i == 0) {
      std::copy(item.variable.binary["KEY"].begin(),
                item.variable.binary["KEY"].end(), key.begin());
    } else if (KEY_BIT == 128) {
      std::copy(decrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                decrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, prev_result);
    } else if (KEY_BIT == 192) {
      std::vector<std::uint8_t> temp_t;
      temp_t.reserve(24);
      temp_t.insert(temp_t.end(), prev_prev_result.end() - 8,
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::copy(decrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                decrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, temp_t);
    } else if (KEY_BIT == 256) {
      std::vector<std::uint8_t> temp_t;
      temp_t.reserve(32);
      temp_t.insert(temp_t.end(), prev_prev_result.begin(),
                    prev_prev_result.end());
      temp_t.insert(temp_t.end(), prev_result.begin(), prev_result.end());
      std::copy(decrypt_test_vectors[i - 1].variable.binary["KEY"].begin(),
                decrypt_test_vectors[i - 1].variable.binary["KEY"].end(),
                key.begin());
      bedrock::util::XorInplace(key, temp_t);
    }
    std::array<std::uint8_t, 16> IV;
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
              << bedrock::util::BytesToHexStr(item.variable.binary["KEY"])
              << " (" << static_cast<int>(item.variable.binary["KEY"][0])
              << ", " << static_cast<int>(item.variable.binary["KEY"][1])
              << " ... " << static_cast<int>(item.variable.binary["KEY"][14])
              << ", " << static_cast<int>(item.variable.binary["KEY"][15])
              << " "
              << "\n";
    std::cout << "IV: "
              << bedrock::util::BytesToHexStr(item.variable.binary["IV"])
              << " (" << static_cast<int>(item.variable.binary["IV"][0]) << ", "
              << static_cast<int>(item.variable.binary["IV"][1]) << " ... "
              << static_cast<int>(item.variable.binary["IV"][14]) << ", "
              << static_cast<int>(item.variable.binary["IV"][15]) << ") "
              << "\n";
    std::cout << "CIPHERTEXT: "
              << bedrock::util::BytesToHexStr(
                     item.variable.binary["CIPHERTEXT"])
              << " (" << static_cast<int>(item.variable.binary["CIPHERTEXT"][0])
              << ", " << static_cast<int>(item.variable.binary["CIPHERTEXT"][1])
              << " ... "
              << static_cast<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 2])
              << ", "
              << static_cast<int>(
                     item.variable
                         .binary["CIPHERTEXT"]
                                [item.variable.binary["CIPHERTEXT"].size() - 1])
              << ") "
              << "\n";

    std::vector<std::uint8_t> next_input;
    next_input.resize(item.variable.binary["CIPHERTEXT"].size());
    std::copy(item.variable.binary["CIPHERTEXT"].begin(),
              item.variable.binary["CIPHERTEXT"].end(), next_input.begin());

    for (std::uint32_t j = 0; j < 1000; j++) {
      std::vector<std::uint8_t> result;
      result.reserve(item.variable.binary["PLAINTEXT"].size());

      for (std::uint32_t k = 0; k * 16 + 16 <= next_input.size(); k++) {
        std::vector<std::uint8_t> input_block(16);
        std::copy(k * 16 + next_input.begin(), k * 16 + next_input.begin() + 16,
                  input_block.begin());
        std::vector<std::uint8_t> output_block(16);

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
            << bedrock::util::BytesToHexStr(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"])
            << " ("
            << static_cast<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][0])
            << ", "
            << static_cast<int>(
                   sample.variable.binary["Intermediate Vaue PLAINTEXT"][1])
            << " ... "
            << static_cast<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               2])
            << ", "
            << static_cast<int>(
                   sample.variable
                       .binary["Intermediate Vaue PLAINTEXT"]
                              [sample.variable
                                   .binary["Intermediate Vaue PLAINTEXT"]
                                   .size() -
                               1])
            << ") "
            << "\n";
        std::cout << "\t" << "Intermediate Vaue PLAINTEXT: "
                  << bedrock::util::BytesToHexStr(result) << " (" << result[0]
                  << ", " << result[1] << " ... " << result[result.size() - 2]
                  << ", " << result[result.size() - 1] << " "
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
