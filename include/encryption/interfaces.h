#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_INTERFACES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_INTERFACES_H_

#include <cstdint>
#include <span>

#include "common/interfaces.h"

namespace bedrock::cipher {

enum class BlockCipherErrorStatus { kSuccess, kFailure };

class BlockCipherAlgorithm : public Validatable {
 public:
  BlockCipherAlgorithm();
  virtual ~BlockCipherAlgorithm() override;

  virtual BlockCipherErrorStatus Encrypt(const std::span<const std::byte> block,
                                         std::span<std::byte> out) = 0;
  virtual BlockCipherErrorStatus Decrypt(const std::span<const std::byte> block,
                                         std::span<std::byte> out) = 0;

  virtual std::uint32_t GetKeySize() = 0;
  virtual std::uint32_t GetBlockSize() = 0;
};

}  // namespace bedrock::cipher

#endif
