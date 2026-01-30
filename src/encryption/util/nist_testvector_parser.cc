#include "encryption/util/nist_testvector_parser.h"

#include <fstream>
#include <regex>

#include "encryption/util/helper.h"

namespace bedrock::util::NISTTestVectorParser {

ReturnStatusCode ParseHashVector(const std::filesystem::path& file_path,
                                 std::vector<NISTTestVariables>& test_vectors) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");

  if (!file.is_open()) {
    NISTTestVariables error_object;
    error_object.binary["error_msg"] = StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  int count = 0;

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestVariables());
  }

  while (std::getline(file, line)) {
    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (!std::regex_match(line, matches, variable)) {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (var_name == "Len" ||
        std::regex_match(var_name, std::regex(".*COUNT.*"))) {
      if (test_vectors[count].integer.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].integer[var_name] =
          std::stoul(var_value, nullptr, 10);
    } else {
      if (test_vectors[count].binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].binary[var_name] = HexStrToBytes(var_value);
    }
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseHashMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex variable_indented(
      "\\s+([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");

  NISTTestMonteSample sample;
  std::queue<NISTTestMonteSample> samples = {};
  std::uint32_t count = 0;
  bool indented = false;
  bool pre_indented = false;

  if (!file.is_open()) {
    NISTTestMonteStage error_object;
    error_object.variable.binary["error_msg"] =
        StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestMonteStage());
  }

  while (std::getline(file, line)) {
    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (std::regex_match(line, matches, variable_indented)) {
      indented = true;
    } else if (std::regex_match(line, matches, variable)) {
      indented = false;
    } else {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (indented) {
      if (var_name == "i" ||
          std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        if (sample.variable.integer.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.integer.clear();
          sample.variable.binary.clear();
        }
        sample.variable.integer[var_name] = std::stoul(var_value, nullptr, 10);
      } else {
        if (sample.variable.binary.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.integer.clear();
          sample.variable.binary.clear();
        }
        sample.variable.binary[var_name] = HexStrToBytes(var_value);
      }
    } else {
      if (pre_indented) {
        test_vectors[count].samples.push(sample);
        sample.variable.integer.clear();
        sample.variable.binary.clear();
      }

      if (test_vectors[count].variable.integer.contains(var_name) ||
          test_vectors[count].variable.binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestMonteStage());
      }
      if (std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        test_vectors[count].variable.integer[var_name] =
            std::stoul(var_value, nullptr, 10);
      } else {
        test_vectors[count].variable.binary[var_name] =
            HexStrToBytes(var_value);
      }
    }

    pre_indented = indented;
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseCipherVector(const std::filesystem::path& file_path,
                                   std::vector<NISTTestVariables>& test_vectors,
                                   VectorCategory category) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex encrypt("\\[ENCRYPT\\]");
  std::regex decrypt("\\[DECRYPT\\]");
  bool reading = false;

  if (!file.is_open()) {
    NISTTestVariables error_object;
    error_object.binary["error_msg"] = StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  int count = 0;

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestVariables());
  }

  while (std::getline(file, line)) {
    if (category == VectorCategory::kEncrypt &&
        std::regex_search(line, encrypt)) {
      reading = true;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, decrypt)) {
      reading = true;
    } else if (category == VectorCategory::kEncrypt &&
               std::regex_search(line, decrypt)) {
      reading = false;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, encrypt)) {
      reading = false;
    }

    if (!reading) {
      continue;
    }

    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (!std::regex_match(line, matches, variable)) {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (var_name == "Len" ||
        std::regex_match(var_name, std::regex(".*COUNT.*"))) {
      if (test_vectors[count].integer.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].integer[var_name] =
          std::stoul(var_value, nullptr, 10);
    } else {
      if (test_vectors[count].binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestVariables());
      }
      test_vectors[count].binary[var_name] = HexStrToBytes(var_value);
    }
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseCipherMonteVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestMonteStage>& test_vectors, VectorCategory category) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex word_size(
      "\\[\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9]+)\\s*\\]");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex variable_indented(
      "\\s+([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-fA-F0-9\\.]+)\\s*");
  std::regex encrypt("\\[ENCRYPT\\]");
  std::regex decrypt("\\[DECRYPT\\]");
  bool reading = false;

  NISTTestMonteSample sample;
  std::queue<NISTTestMonteSample> samples = {};
  std::uint32_t count = 0;
  bool indented = false;
  bool pre_indented = false;

  if (!file.is_open()) {
    NISTTestMonteStage error_object;
    error_object.variable.binary["error_msg"] =
        StrToBytes("Error opening file.");
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  if (test_vectors.size() <= count) {
    test_vectors.push_back(NISTTestMonteStage());
  }

  while (std::getline(file, line)) {
    if (category == VectorCategory::kEncrypt &&
        std::regex_search(line, encrypt)) {
      reading = true;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, decrypt)) {
      reading = true;
    } else if (category == VectorCategory::kEncrypt &&
               std::regex_search(line, decrypt)) {
      reading = false;
    } else if (category == VectorCategory::kDecrypt &&
               std::regex_search(line, encrypt)) {
      reading = false;
    }

    if (!reading) {
      continue;
    }

    std::smatch matches;
    if (std::regex_match(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_match(line, word_size)) {
      continue;
    }

    if (std::regex_match(line, matches, variable_indented)) {
      indented = true;
    } else if (std::regex_match(line, matches, variable)) {
      indented = false;
    } else {
      continue;
    }
    std::string var_name = matches[1];
    std::string var_value = matches[2];

    if (indented) {
      if (var_name == "i" ||
          std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        if (sample.variable.integer.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.integer.clear();
          sample.variable.binary.clear();
        }
        sample.variable.integer[var_name] = std::stoul(var_value, nullptr, 10);
      } else {
        if (sample.variable.binary.contains(var_name)) {
          test_vectors[count].samples.push(sample);
          sample.variable.integer.clear();
          sample.variable.binary.clear();
        }
        sample.variable.binary[var_name] = HexStrToBytes(var_value);
      }
    } else {
      if (pre_indented) {
        test_vectors[count].samples.push(sample);
        sample.variable.integer.clear();
        sample.variable.binary.clear();
      }

      if (test_vectors[count].variable.integer.contains(var_name) ||
          test_vectors[count].variable.binary.contains(var_name)) {
        count++;
        test_vectors.push_back(NISTTestMonteStage());
      }
      if (std::regex_match(var_name, std::regex(".*COUNT.*"))) {
        test_vectors[count].variable.integer[var_name] =
            std::stoul(var_value, nullptr, 10);
      } else {
        test_vectors[count].variable.binary[var_name] =
            HexStrToBytes(var_value);
      }
    }

    pre_indented = indented;
  }

  return ReturnStatusCode::kSuccess;
}

ReturnStatusCode ParseHashDRBGVector(
    const std::filesystem::path& file_path,
    std::vector<NISTTestDRBGHashAlgorithm>& test_vectors) {
  std::ifstream file(file_path);
  std::string line;

  std::regex comment("^(.*?)#.*$");
  std::regex constant(".*\\[(.*)\\].*");
  std::regex variable("\\s*([a-zA-Z0-9 ]+)\\s\\s*=\\s*([a-zA-Z0-9\\.]*)\\s*");

  std::regex instantiate("\\*\\*\\sINSTANTIATE:");
  std::regex reseed("\\*\\*\\sRESEED:");
  std::regex generate("\\*\\*\\sGENERATE.*:");

  std::string hashALGORITHM_name;
  std::vector<std::uint8_t> entropy_input = {};
  std::vector<std::uint8_t> nonce = {};
  std::vector<std::uint8_t> personalization_string = {};
  std::vector<std::uint8_t> additional_input = {};
  std::vector<std::uint8_t> returned_bits = {};
  bool prediction_resistance_flag = false;

  NISTTestDRBGHashState hash_state;
  bool V_parsed = false;
  bool C_parsed = false;
  bool reseed_counter_parsed = false;
  DRBGFunctionName function_name = DRBGFunctionName::kError;
  std::uint32_t returned_bits_len = 0;

  if (!file.is_open()) {
    NISTTestDRBGHashAlgorithm error_object;
    error_object.hashALGORITHM_name = "Error opening file.";
    test_vectors.push_back(error_object);
    return ReturnStatusCode::kError;
  }

  while (std::getline(file, line)) {
    std::smatch matches;
    bool is_constant = false;

    if (std::regex_search(line, matches, comment)) {
      line = matches[1];
    }

    if (std::regex_search(line, matches, constant)) {
      line = matches[1];
      is_constant = true;
    } else {
      is_constant = false;
    }

    if (std::regex_search(line, matches, variable)) {
      std::string var_name = matches[1];
      std::string var_value = matches[2];

      if (is_constant && var_name == "PredictionResistance" &&
          var_value == "True") {
        prediction_resistance_flag = true;
        continue;
      } else if (is_constant && var_name == "PredictionResistance" &&
                 var_value == "False") {
        prediction_resistance_flag = false;
        continue;
      }

      // because all of it was too big
      if (!is_constant && hashALGORITHM_name != "SHA-256") {
        continue;
      }

      if (var_name == "EntropyInput" || var_name == "EntropyInputReseed" ||
          var_name == "EntropyInputPR") {
        entropy_input = HexStrToBytes(var_value);
      } else if (var_name == "Nonce") {
        nonce = HexStrToBytes(var_value);
      } else if (var_name == "PersonalizationString") {
        personalization_string = HexStrToBytes(var_value);
      } else if (var_name == "AdditionalInput" ||
                 var_name == "AdditionalInputReseed") {
        additional_input = HexStrToBytes(var_value);
      } else if (var_name == "V") {
        hash_state.V = HexStrToBytes(var_value);
        V_parsed = true;
      } else if (var_name == "C") {
        hash_state.C = HexStrToBytes(var_value);
        C_parsed = true;
      } else if (var_name == "reseed counter") {
        hash_state.reseed_counter = std::stoul(var_value, nullptr, 10);
        reseed_counter_parsed = true;
      } else if (var_name == "ReturnedBits") {
        returned_bits = HexStrToBytes(var_value);
      } else if (var_name == "ReturnedBitsLen") {
        returned_bits_len = std::stoul(var_value, nullptr, 10);
      }
    } else if (is_constant) {
      hashALGORITHM_name = line;
    }

    if (std::regex_search(line, matches, instantiate))
      function_name = DRBGFunctionName::kInstantiate;
    if (std::regex_search(line, matches, reseed))
      function_name = DRBGFunctionName::kReseed;
    if (std::regex_search(line, matches, generate))
      function_name = DRBGFunctionName::kGenerate;

    if (V_parsed && C_parsed && reseed_counter_parsed) {
      NISTTestDRBGHashStep step;
      step.function_name = function_name;
      step.entropy_input = entropy_input;
      step.nonce = nonce;
      step.personalization_string = personalization_string;
      step.additional_input = additional_input;
      step.prediction_resistance_flag = prediction_resistance_flag;
      step.internal_state = hash_state;
      step.returned_bits = returned_bits;

      if (test_vectors.size() == 0 ||
          test_vectors.back().hashALGORITHM_name != hashALGORITHM_name) {
        NISTTestDRBGHashAlgorithm stage;
        stage.hashALGORITHM_name = hashALGORITHM_name;
        test_vectors.push_back(stage);
      }
      if (function_name == DRBGFunctionName::kInstantiate) {
        NISTTestDRBGHashStage new_stage;
        test_vectors.back().stages.push_back(new_stage);
      }
      test_vectors.back().stages.back().steps.push_back(step);
      test_vectors.back().stages.back().ReturnedBitsLen = returned_bits_len;

      entropy_input.clear();
      nonce.clear();
      personalization_string.clear();

      additional_input.clear();
      returned_bits.clear();
      hash_state = NISTTestDRBGHashState();
      V_parsed = false;
      C_parsed = false;
      reseed_counter_parsed = false;
      function_name = DRBGFunctionName::kError;
    }
  }

  return ReturnStatusCode::kSuccess;
}

}  // namespace bedrock::util::NISTTestVectorParser
