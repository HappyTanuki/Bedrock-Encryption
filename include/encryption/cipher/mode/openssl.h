#pragma once
#include "operation.h"

namespace bedrock::cipher::op_mode {

#if ENCRYPTION_USE_OPENSSL
// openssl 운영 모드
class OPENSSL : public OperationMode {
 public:
  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) final override;
};
#endif

};  // namespace bedrock::cipher::op_mode
