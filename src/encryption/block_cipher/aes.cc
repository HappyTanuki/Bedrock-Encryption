#include "encryption/block_cipher/aes.h"

#include <emmintrin.h>

#include <cassert>
#include <cstring>

#include "common/intrinsics.h"
#include "encryption/interfaces.h"

namespace bedrock::cipher {

enum IntrinSet { kAESNI, kSSE2, kSSSE3 };

static bool IntrinEnabled(IntrinSet target) {
  static bedrock::intrinsic::Register reg =
      bedrock::intrinsic::GetCPUFeatures();

  static std::array<bool, 3> enabled = {
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "AESNI"),
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSE2"),
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSSE3")};

  switch (target) {
    case kAESNI:
      return enabled[target];
    case kSSE2:
      return enabled[target];
    case kSSSE3:
      return enabled[target];
    default:
      return false;
  }
}

AESPicker::AESPicker() = default;

std::unique_ptr<AESImpl> AESPicker::PickImpl(
    std::span<const std::uint8_t> key) {
  if (key.size() != 32 && key.size() != 24 && key.size() != 16) {
    return nullptr;
  }

  std::unique_ptr<AESImpl> impl;

  if (IntrinEnabled(IntrinSet::kAESNI) && IntrinEnabled(IntrinSet::kSSE2) &&
      IntrinEnabled(IntrinSet::kSSSE3)) {
    impl = std::make_unique<AES_NI>();
  } else {
    impl = std::make_unique<AES_SOFT>();
  }

  impl->SetKey(key);
  return impl;
}

AESImpl::~AESImpl() noexcept = default;

ErrorStatus AESImpl::Encrypt(std::span<const std::uint8_t> block,
                             std::span<std::uint8_t> out) noexcept {
  if (!IsValid() && !key.IsValid()) {
    return ErrorStatus::kFailure;
  }

  std::uint32_t Nr = key.size / 32 + 6;
  std::uint32_t round_keys_size = Nr + 1;
  std::span<std::array<std::uint8_t, 16>> round_keys_view = key.enc_round_keys;
  if (round_keys_view.size() != 0 && round_keys_view[0].size() != 16) {
    return ErrorStatus::kFailure;
  }

  EncryptImpl(round_keys_view.subspan(0, round_keys_size), block, out);

  return ErrorStatus::kSuccess;
}
ErrorStatus AESImpl::Decrypt(std::span<const std::uint8_t> block,
                             std::span<std::uint8_t> out) noexcept {
  if (!IsValid() && !key.IsValid()) {
    return ErrorStatus::kFailure;
  }

  std::uint32_t Nr = key.size / 32 + 6;
  std::uint32_t round_keys_size = Nr + 1;
  std::span<std::array<std::uint8_t, 16>> round_keys_view = key.dec_round_keys;
  if (round_keys_view.size() != 0 && round_keys_view[0].size() != 16) {
    return ErrorStatus::kFailure;
  }

  DecryptImpl(round_keys_view.subspan(0, round_keys_size), block, out);

  return ErrorStatus::kSuccess;
}

ErrorStatus AESImpl::SetKey(const BlockCipherKey<16>& key_in) noexcept {
  if (!key_in.IsValid()) {
    return ErrorStatus::kFailure;
  }
  key = key_in;
  this->valid = true;

  return ErrorStatus::kSuccess;
}

ErrorStatus AESImpl::SetKey(std::span<const std::uint8_t> key_in) noexcept {
  if (key_in.size() != 16 && key_in.size() != 24 && key_in.size() != 32) {
    return ErrorStatus::kFailure;
  }
  std::uint16_t key_size = key_in.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  key.enc_round_keys.resize(Nr + 1);
  key.dec_round_keys.resize(Nr + 1);

  KeyExpantion(key_in, key.enc_round_keys, key.dec_round_keys);
  key.size = key_size;
  key.valid = true;
  this->valid = true;

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher