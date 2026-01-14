#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CBC_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CBC_H_

#include <cmath>
#include <cstring>

#include "operation.h"

namespace bedrock::cipher::op_mode {

// CBC 운영 모드
class CBC : public OperationMode {
 public:
  using OperationMode::OperationMode;

  BlockCipherErrorStatus Process(const std::span<const std::byte> input,
                                 std::span<std::byte> output) final override;

  bool IsValid() const final override { return true; }
};

};  // namespace bedrock::cipher::op_mode

#endif
