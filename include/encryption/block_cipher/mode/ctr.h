#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CTR_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CTR_H_

#include "operation.h"

namespace bedrock::cipher::op_mode {

class CTR : public OperationMode {
 public:
  using OperationMode::OperationMode;

  CTR(std::unique_ptr<BlockCipherAlgorithm> algorithm,
      const std::span<const std::byte> IV, std::uint32_t m_bits = 64);

  BlockCipherErrorStatus Process(const std::span<const std::byte> input,
                                 std::span<std::byte> output) final override;

  bool IsValid() const final override { return valid; }

 private:
  std::uint32_t m;
  bool valid = false;
};

};  // namespace bedrock::cipher::op_mode

#endif
