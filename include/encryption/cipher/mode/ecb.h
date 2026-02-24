#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_ECB_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_ECB_H_

#include "operation.h"

namespace bedrock::cipher::op_mode {

class ECB : public OperationMode {
 public:
  ECB() { algorithm_name = "ECB"; }

  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) final override;
};

}  // namespace bedrock::cipher::op_mode

#endif
