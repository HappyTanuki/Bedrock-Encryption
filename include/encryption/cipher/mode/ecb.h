#pragma once
#include "operation.h"

namespace bedrock::cipher::op_mode {

class ECB : public OperationMode {
 public:
  ECB() { algorithm_name = "ECB"; }

  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) final;
};

}  // namespace bedrock::cipher::op_mode
