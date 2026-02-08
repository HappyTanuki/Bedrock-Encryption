#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_GCM_H_

#include <cmath>
#include <cstring>

#include "ctr.h"

namespace bedrock::cipher::op_mode {

// GCM 운영 모드
template <std::uint32_t Blocksize = 16>
class GCM : public CTR<Blocksize> {
 public:
  using CTR<Blocksize>::CTR;

  GCM(std::unique_ptr<BlockCipherAlgorithm<Blocksize>> algorithm,
      const std::span<const std::uint8_t> IV, std::uint32_t m_bits = 64);

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) final override;

  bool IsValid() const final override;
};

template <std::uint32_t BlockSize>
GCM<BlockSize>::GCM(std::unique_ptr<BlockCipherAlgorithm<BlockSize>> algorithm,
                    const std::span<const std::uint8_t> IV,
                    std::uint32_t m_bits)
    : CTR<BlockSize>(std::move(algorithm), IV, m_bits) {}

template <std::uint32_t BlockSize>
ErrorStatus GCM<BlockSize>::Process(const std::span<const std::uint8_t> input,
                                    std::span<std::uint8_t> output) {
  return ErrorStatus::kSuccess;
}

template <std::uint32_t BlockSize>
bool GCM<BlockSize>::IsValid() const {
  return true;
}

};  // namespace bedrock::cipher::op_mode

#endif
