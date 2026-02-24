#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_CBC_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_CBC_H_

#include <cmath>
#include <cstring>

#include "operation.h"

namespace bedrock::cipher::op_mode {

// CBC 운영 모드
class CBC : public OperationMode {
 public:
  CBC() { algorithm_name = "CBC"; }

  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) final override;
};

};  // namespace bedrock::cipher::op_mode

#endif
