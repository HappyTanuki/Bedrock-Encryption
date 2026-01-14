#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_NIST_TESTVECTOR_PARSER_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_NIST_TESTVECTOR_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

namespace bedrock::cipher::util::NISTTestVectorParser {

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
  std::unordered_map<std::string, std::vector<std::byte>> binary = {};
};

struct NISTTestMonteSample {
  NISTTestVariables variable = {};
};

struct NISTTestMonteStage {
  std::queue<NISTTestMonteSample> samples = {};
  NISTTestVariables variable = {};
};

struct NISTTestDRBGHashState {
  std::vector<std::byte> V = {};
  std::vector<std::byte> C = {};
  std::uint64_t reseed_counter = 0;
};

struct NISTTestDRBGHashStep {
  DRBGFunctionName function_name;
  std::vector<std::byte> additional_input = {};
  std::vector<std::byte> entropy_input = {};
  std::vector<std::byte> nonce = {};
  std::vector<std::byte> personalization_string = {};
  std::vector<std::byte> returned_bits = {};
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

}  // namespace bedrock::cipher::util::NISTTestVectorParser

#endif
