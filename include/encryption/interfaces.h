#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_INTERFACES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_INTERFACES_H_

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "common/interfaces.h"

namespace bedrock::cipher {

enum class ErrorStatus { kSuccess, kFailure };

template <std::uint32_t Blocksize = 16>
class BlockCipherKey : public Validatable {
 public:
  // unit is bit
  std::uint32_t size = 0;

  alignas(16) std::vector<std::array<std::uint8_t, Blocksize>> enc_round_keys;
  alignas(16) std::vector<std::array<std::uint8_t, Blocksize>> dec_round_keys;

  bool IsValid() const noexcept override { return valid; }

  bool valid = false;
};

template <std::uint32_t Blocksize = 16>
class BlockCipherAlgorithm : public Validatable {
 public:
  virtual ~BlockCipherAlgorithm() noexcept override = default;

  virtual ErrorStatus Encrypt(const std::span<const std::uint8_t> block,
                              std::span<std::uint8_t> out) noexcept = 0;
  virtual ErrorStatus Decrypt(const std::span<const std::uint8_t> block,
                              std::span<std::uint8_t> out) noexcept = 0;

  virtual ErrorStatus SetKey(
      const BlockCipherKey<Blocksize>& key_in) noexcept = 0;
  virtual ErrorStatus SetKey(std::span<const std::uint8_t> key_in) noexcept = 0;
  virtual void GetKey(BlockCipherKey<Blocksize>& key_out) noexcept = 0;

  virtual std::uint32_t GetKeySize() const noexcept = 0;
  virtual std::uint32_t GetBlockSize() const noexcept = 0;

 protected:
  BlockCipherKey<Blocksize> key;
};

}  // namespace bedrock::cipher

#endif
