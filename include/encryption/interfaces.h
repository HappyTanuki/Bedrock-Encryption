#pragma once
#if ENCRYPTION_USE_OPENSSL
  #include <openssl/evp.h>
#endif

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "common/interfaces.h"

namespace bedrock::cipher {

enum class ErrorStatus { kSuccess, kFailure };

class BlockCipherCTX : public Validatable {
 public:
  BlockCipherCTX() = default;
  BlockCipherCTX(const BlockCipherCTX&) = delete;
  BlockCipherCTX& operator=(const BlockCipherCTX&) = delete;

  virtual ~BlockCipherCTX() override;
  // unit is bit
  std::uint32_t key_size = 0;
  std::uint32_t block_size = 0;

  alignas(16) std::vector<std::array<std::uint8_t, 16>> enc_round_keys;
  alignas(16) std::vector<std::array<std::uint8_t, 16>> dec_round_keys;

  alignas(16) std::vector<std::uint8_t> state;
  
#if ENCRYPTION_USE_OPENSSL
  ::EVP_CIPHER_CTX* evp_ctx = nullptr;
  ::EVP_CIPHER* evp_cipher = nullptr;
#endif

  std::uint32_t Nr = 0;
  std::uint32_t Nk = 0;

  std::span<std::array<std::uint8_t, 16>> enc_round_keys_view(
      std::size_t size = 0) {
    std::span<std::array<std::uint8_t, 16>> view(enc_round_keys);
    return view.subspan(0, size);
  }
  std::span<std::array<std::uint8_t, 16>> dec_round_keys_view(
      std::size_t size = 0) {
    std::span<std::array<std::uint8_t, 16>> view(dec_round_keys);
    return view.subspan(0, size);
  }

  bool IsValid() const noexcept override { return valid; }

  bool valid = false;
};

class BlockCipherAlgorithm {
 public:
  virtual ~BlockCipherAlgorithm() noexcept;

  virtual ErrorStatus Encrypt(BlockCipherCTX& ctx,
                              const std::span<const std::uint8_t> block,
                              std::span<std::uint8_t> out) const noexcept = 0;
  virtual ErrorStatus Decrypt(BlockCipherCTX& ctx,
                              const std::span<const std::uint8_t> block,
                              std::span<std::uint8_t> out) const noexcept = 0;
  virtual ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                                   BlockCipherCTX& ctx) const noexcept = 0;

  virtual std::uint32_t GetBlockSize() const noexcept = 0;
  virtual const char* GetAlgorithmName() const noexcept = 0;
};

}  // namespace bedrock::cipher
