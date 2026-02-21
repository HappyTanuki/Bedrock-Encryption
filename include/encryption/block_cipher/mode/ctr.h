#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CTR_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CTR_H_

#include "operation.h"

namespace bedrock::cipher::op_mode {

class CTR : public OperationMode {
 public:
  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output) override;

  bool IsValid() const override { return valid; }

 private:
  std::uint32_t m;
  bool valid = false;
};

};  // namespace bedrock::cipher::op_mode

#endif
