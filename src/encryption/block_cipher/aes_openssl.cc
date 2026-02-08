#include <cassert>
#include <cstring>

#include "encryption/block_cipher/aes.h"

namespace bedrock::cipher {

AES_OPEN_SSL::~AES_OPEN_SSL() = default;

void AES_OPEN_SSL::EncryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  return;
}

void AES_OPEN_SSL::DecryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  return;
}

void AES_OPEN_SSL::KeyExpantion(
    std::span<const std::uint8_t> key,
    std::span<std::array<std::uint8_t, 16>> enc_round_keys,
    std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept {
  return;
}

}  // namespace bedrock::cipher