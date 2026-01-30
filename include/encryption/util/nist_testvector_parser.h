#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_NIST_TESTVECTOR_PARSER_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_NIST_TESTVECTOR_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

namespace bedrock::util::NISTTestVectorParser {

enum class ReturnStatusCode { kSuccess = 0, kError = -1 };
enum class VectorCategory { kEncrypt = 0, kDecrypt = 1 };
enum class DRBGFunctionName {
  kError = 0,
  kInstantiate = 1,
  kGenerate = 2,
  kReseed = 3
};

struct NISTTestVariables {
  std::unordered_map<std::string, std::uint32_t> integer = {};
  std::unordered_map<std::string, std::vector<std::uint8_t>> binary = {};
};

struct NISTTestMonteSample {
  NISTTestVariables variable = {};
};

struct NISTTestMonteStage {
  std::queue<NISTTestMonteSample> samples = {};
  NISTTestVariables variable = {};
};

struct NISTTestDRBGHashState {
  std::vector<std::uint8_t> V = {};
  std::vector<std::uint8_t> C = {};
  std::uint64_t reseed_counter = 0;
};

struct NISTTestDRBGHashStep {
  DRBGFunctionName function_name;
  std::vector<std::uint8_t> additional_input = {};
  std::vector<std::uint8_t> entropy_input = {};
  std::vector<std::uint8_t> nonce = {};
  std::vector<std::uint8_t> personalization_string = {};
  std::vector<std::uint8_t> returned_bits = {};
  bool prediction_resistance_flag = false;
  NISTTestDRBGHashState internal_state = {};
};

struct NISTTestDRBGHashStage {
  std::uint32_t ReturnedBitsLen = 0;
  std::vector<NISTTestDRBGHashStep> steps = {};
};

struct NISTTestDRBGHashAlgorithm {
  std::string hashALGORITHM_name;
  std::vector<NISTTestDRBGHashStage> stages = {};
};

ReturnStatusCode ParseHashVector(const std::filesystem::path& file_path,
                                 std::vector<NISTTestVariables>& test_vectors);
ReturnStatusCode ParseHashMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors);

ReturnStatusCode ParseCipherVector(const std::filesystem::path& file_path,
                                   std::vector<NISTTestVariables>& test_vectors,
                                   VectorCategory category);
ReturnStatusCode ParseCipherMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors, VectorCategory category);

ReturnStatusCode ParseHashDRBGVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestDRBGHashAlgorithm>& test_vectors);

}  // namespace bedrock::util::NISTTestVectorParser

#endif
