#include "algorithm/hash/sha.h"
#include "precomp.h"
#include "util/nist_testvector_parser.h"

namespace NISTTestVectorParser = bedrock::util::NISTTestVectorParser;

int main() {
  bedrock::hash::SHA<256> sha256;

  std::vector<NISTTestVectorParser::NISTTestVariables> test_vectors;
  if (NISTTestVectorParser::ParseHashVector(
          "./tests/test_vector/shabytetestvectors/SHA256LongMsg.rsp",
          test_vectors) != NISTTestVectorParser::ReturnStatusCode::kSuccess) {
    std::string err_string(reinterpret_cast<const char*>(
                               test_vectors.back().binary["error_msg"].data()),
                           test_vectors.back().binary["error_msg"].size());
    std::cout << err_string << std::endl;
    return -1;
  }

  std::cout << "SHA-256 Byte-Oriented LongMsg Stream test: " << std::endl;
  for (NISTTestVectorParser::NISTTestVariables item : test_vectors) {
    std::cout << "Len: " << std::dec << item.integer["Len"] << "\n";
    std::cout << "Msg: 0x";
    for (auto byte : item.binary["Msg"]) {
      std::cout << std::hex << std::to_integer<int>(byte);
    }
    std::cout << "\n";

    file_encrypt::algorithm::HashAlgorithmInputData input_data;
    input_data.bit_length = item.integer["Len"];  // 비트 단위
    input_data.message = item.binary["Msg"];      // std::vector<std::byte>

    // 메시지를 절반으로 나누기
    size_t mid_bytes = item.integer["Len"] / 16;

    file_encrypt::algorithm::HashAlgorithmInputData part1;
    part1.bit_length = mid_bytes * 8;
    part1.message = std::vector<std::byte>(
        input_data.message.begin(), input_data.message.begin() + mid_bytes);

    file_encrypt::algorithm::HashAlgorithmInputData part2;
    part2.bit_length = input_data.bit_length - part1.bit_length;
    part2.message = std::vector<std::byte>(
        input_data.message.begin() + mid_bytes, input_data.message.end());

    // SHA<256> 업데이트
    sha256.Update(part1);
    sha256.Update(part2);
    auto digest = sha256.Digest();
    sha256.Reset();

    std::cout << "MD: 0x";
    for (int i = 0; i < 32; i++) {
      std::cout << std::hex << std::to_integer<int>(digest[i]);
    }
    std::cout << "\n";

    std::cout << "Match: ";
    std::array<std::byte, 32> md = {};
    std::copy(item.binary["MD"].begin(), item.binary["MD"].end(), md.begin());
    if (digest == md) {
      std::cout << "True" << std::endl;
    } else {
      std::cout << "False" << std::endl;
      return -1;
    }
  }

  return 0;
}