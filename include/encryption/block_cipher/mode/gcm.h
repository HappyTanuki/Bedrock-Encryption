#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_

#include <cmath>
#include <cstring>

#include "ctr.h"
#include "operation.h"

namespace bedrock::cipher::op_mode {

// GCM 운영 모드
class GCM : public CTR {
 public:
  using CTR::CTR;

  GCM(std::unique_ptr<BlockCipherAlgorithm> algorithm,
      const std::span<const std::uint8_t> IV, std::uint32_t m_bits = 64);

  BlockCipherErrorStatus Process(const std::span<const std::uint8_t> input,
                                 std::span<std::uint8_t> output) final override;

  bool IsValid() const final override;
};

};  // namespace bedrock::cipher::op_mode

#endif
