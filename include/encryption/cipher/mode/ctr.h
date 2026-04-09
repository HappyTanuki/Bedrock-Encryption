#pragma once
#include "operation.h"

namespace bedrock::cipher::op_mode {

class CTR : public OperationMode {
 public:
  CTR() { algorithm_name = "CTR"; }

  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) override;
};

};  // namespace bedrock::cipher::op_mode
