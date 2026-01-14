#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ECB_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ECB_H_

#include "operation.h"

namespace bedrock::cipher::op_mode {

class ECB : public OperationMode {
 public:
  using OperationMode::OperationMode;

  BlockCipherErrorStatus Process(const std::span<const std::byte> input,
                                 std::span<std::byte> output) final override;

  bool IsValid() const final override { return true; }
};

}  // namespace bedrock::cipher::op_mode

#endif
