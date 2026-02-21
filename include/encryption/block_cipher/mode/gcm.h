#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_

#include <cmath>
#include <cstring>

#include "ctr.h"

namespace bedrock::cipher::op_mode {

// GCM 운영 모드
class GCM : public CTR {
 public:
  ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output) final override;

  bool IsValid() const final override;
};

};  // namespace bedrock::cipher::op_mode

#endif
