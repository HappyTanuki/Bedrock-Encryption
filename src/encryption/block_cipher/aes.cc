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

std::shared_ptr<AESImpl> AESPicker::PickImpl() {
  std::shared_ptr<AESImpl> impl;

  if (IntrinEnabled(IntrinSet::kAESNI) && IntrinEnabled(IntrinSet::kSSE2) &&
      IntrinEnabled(IntrinSet::kSSSE3)) {
    impl = std::make_shared<AES_NI>();
  } else {
    impl = std::make_shared<AES_SOFT>();
  }

  return impl;
}

ErrorStatus AESCTXController::Create(std::shared_ptr<BlockCipherAlgorithm> impl,
                                     std::span<const std::uint8_t> key,
                                     BlockCipherCTX& out) noexcept {
  if (key.size() != 16 && key.size() != 24 && key.size() != 32) {
    return ErrorStatus::kFailure;
  }

  out.key_size = key.size() * 8;
  out.Nk = out.key_size / 32;
  out.Nr = out.Nk + 6;
  out.block_size = 128;
  out.state.resize(out.block_size / 8);
  out.enc_round_keys.resize(out.Nr + 1);
  out.dec_round_keys.resize(out.Nr + 1);

  if (impl->KeyExpantion(key, out) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  out.valid = true;

  return ErrorStatus::kSuccess;
}
ErrorStatus AESCTXController::SetKey(
    std::shared_ptr<BlockCipherAlgorithm> impl, BlockCipherCTX& ctx,
    std::span<const std::uint8_t> key_in) noexcept {
  if (!ctx.IsValid()) {
    return ErrorStatus::kFailure;
  }
  if (key_in.size() != 16 && key_in.size() != 24 && key_in.size() != 32) {
    return ErrorStatus::kFailure;
  }

  if (impl->KeyExpantion(key_in, ctx) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  return ErrorStatus::kSuccess;
}

AESImpl::~AESImpl() noexcept = default;

ErrorStatus AESImpl::Encrypt(BlockCipherCTX& key,
                             std::span<const std::uint8_t> block,
                             std::span<std::uint8_t> out) const noexcept {
  if (!key.IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (key.enc_round_keys_view().size() != 0 &&
      key.enc_round_keys_view()[0].size() != 16) {
    return ErrorStatus::kFailure;
  }

  EncryptImpl(key, block, out);

  return ErrorStatus::kSuccess;
}
ErrorStatus AESImpl::Decrypt(BlockCipherCTX& key,
                             std::span<const std::uint8_t> block,
                             std::span<std::uint8_t> out) const noexcept {
  if (!key.IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (key.dec_round_keys_view().size() != 0 &&
      key.dec_round_keys_view()[0].size() != 16) {
    return ErrorStatus::kFailure;
  }

  DecryptImpl(key, block, out);

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher