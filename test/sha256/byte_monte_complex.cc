#include "algorithm/hash/sha.h"
#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::util::NISTTestVectorParser;

static std::vector<std::byte> ByteStitch(const std::vector<std::byte>& a,
                                         const std::vector<std::byte>& b,
                                         const std::vector<std::byte>& c) {
  std::vector<std::byte> result;
  result.reserve(a.size() + b.size() + c.size());
  for (size_t i = 0; i < a.size(); ++i) {
    result.push_back(a[i]);
  }
  for (size_t i = 0; i < b.size(); ++i) {
    result.push_back(b[i]);
  }
  for (size_t i = 0; i < c.size(); ++i) {
    result.push_back(c[i]);
  }
  return result;
}

int main() {
  bedrock::hash::SHA<256> sha256;

  std::vector<NISTTestVectorParser::NISTTestMonteStage> test_vectors;
  if (NISTTestVectorParser::ParseHashMonteVector(
          "./tests/test_vector/shabytetestvectors/SHA256Monte.txt",
          test_vectors) != NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(
        reinterpret_cast<const char*>(
            test_vectors.back().variable.binary["error_msg"].data()),
        test_vectors.back().variable.binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::vector<std::byte> seed = test_vectors[0].variable.binary["Seed"];

  std::cout << "SHA-256 Monte-Carlo Byte-Oriented complex test: " << std::endl;
  for (NISTTestVectorParser::NISTTestMonteStage item : test_vectors) {
    std::cout << "COUNT: " << std::dec << item.variable.integer["COUNT"]
              << "\n";

    std::array<std::vector<std::byte>, 1003> MD;
    std::array<std::vector<std::byte>, 1003> M;
    MD[0] = seed;
    MD[1] = seed;
    MD[2] = seed;

    for (int i = 3; i < 1003; i++) {
      file_encrypt::algorithm::HashAlgorithmInputData message_input_data;
      message_input_data.bit_length = 256 * 3;
      M[i] = ByteStitch(MD[i - 3], MD[i - 2], MD[i - 1]);
      message_input_data.message = M[i];
      auto digest = sha256.Digest(message_input_data);
      MD[i] = std::vector<std::byte>(digest.begin(), digest.end());

      if (!item.samples.empty() &&
          item.samples.front().variable.integer["i"] == i) {
        file_encrypt::util::NISTTestVectorParser::NISTTestMonteSample sample =
            item.samples.front();
        item.samples.pop();
        std::cout << "  i: " << std::dec << sample.variable.integer["i"]
                  << "\n";
        std::cout << "  M: 0x";
        for (auto byte : sample.variable.binary["M"]) {
          std::cout << std::hex << std::to_integer<int>(byte);
        }
        std::cout << "\n";
        std::cout << "  MDi: 0x";
        for (auto byte : sample.variable.binary["MDi"]) {
          std::cout << std::hex << std::to_integer<int>(byte);
        }
        std::cout << "\n";

        if (sample.variable.binary["M"] != M[i]) {
          std::cout << "Mismatch M" << std::endl;
          std::cout << "Computed M: 0x";
          for (auto byte : M[i]) {
            std::cout << std::hex << std::to_integer<int>(byte);
          }
          std::cout << "\n";
          return -1;
        }
        if (sample.variable.binary["MDi"] != MD[i]) {
          std::cout << "Mismatch MDi" << std::endl;
          std::cout << "Computed MDi: 0x";
          for (auto byte : MD[i]) {
            std::cout << std::hex << std::to_integer<int>(byte);
          }
          std::cout << "\n";
          return -1;
        }
      }
    }

    MD[item.variable.integer["COUNT"]] = MD[1002];
    seed = MD[1002];

    std::cout << "MD: 0x";
    for (int i = 0; i < 32; i++) {
      std::cout << std::hex
                << std::to_integer<int>(item.variable.binary["MD"][i]);
    }
    std::cout << "\n";

    std::cout << "Match: ";
    if (seed == item.variable.binary["MD"]) {
      std::cout << "True" << std::endl;
    } else {
      std::cout << "False" << std::endl;
      return -1;
    }
  }

  return 0;
}