#pragma once
#include "operation.h"

namespace bedrock::cipher::op_mode {

// CBC 운영 모드
class CBC : public OperationMode {
 public:
  CBC() { algorithm_name = "CBC"; }

  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) final;
};

};  // namespace bedrock::cipher::op_mode
