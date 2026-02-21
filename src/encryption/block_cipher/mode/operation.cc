#include "encryption/block_cipher/mode/operation.h"

#include "encryption/block_cipher/aes.h"
#include "encryption/block_cipher/mode/cbc.h"
#include "encryption/block_cipher/mode/ctr.h"
#include "encryption/block_cipher/mode/ecb.h"
#include "encryption/block_cipher/mode/gcm.h"

namespace bedrock::cipher::op_mode {

ModeContext::~ModeContext() = default;
OperationMode::~OperationMode() = default;

std::shared_ptr<OperationMode> ImplPicker::PickImpl(std::string mode) {
  if (mode == "CBC") {
    return std::make_shared<CBC>();
  } else if (mode == "CTR") {
    return std::make_shared<CTR>();
  } else if (mode == "ECB") {
    return std::make_shared<ECB>();
  } else if (mode == "GCM") {
    return std::make_shared<GCM>();
  } else {
    return nullptr;
  }
}

ErrorStatus CTXController::Create(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& out, std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> iv, CipherMode mode,
    std::uint32_t m_bits) noexcept {
  if (impl == nullptr) {
    return ErrorStatus::kFailure;
  }

  if (AESCTXController::Create(impl, key, out) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  out.iv = std::vector<std::uint8_t>(iv.begin(), iv.end());
  out.iv.resize(out.block_size / 8);
  out.mode = mode;
  out.m_bits = m_bits;
  out.prev_vector = std::vector<std::uint8_t>(iv.begin(), iv.end());
  out.prev_vector.resize(out.block_size / 8);
  out.buffer.resize(out.block_size / 8);

  if (out.m_bits != 0) {
    std::uint32_t block_bytes = out.block_size / 8;
    std::uint32_t counter_bytes = (m_bits + 7) / 8;

    for (std::uint32_t i = block_bytes - 1; i > block_bytes - counter_bytes;
         i--) {
      out.prev_vector[i] = static_cast<std::uint8_t>(0x00);
      m_bits -= 8;
    }
    out.prev_vector[block_bytes - counter_bytes] &=
        static_cast<std::uint8_t>(0xFF << m_bits);
  }

  out.valid = true;

  return ErrorStatus::kSuccess;
}
ErrorStatus CTXController::SetKey(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, std::span<const std::uint8_t> key_in) noexcept {
  if (impl == nullptr || !ctx.IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (AESCTXController::SetKey(impl, ctx, key_in) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  return ErrorStatus::kSuccess;
}
ErrorStatus CTXController::SetIV(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, std::span<const std::uint8_t> iv_in) noexcept {
  if (impl == nullptr || !ctx.IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (iv_in.size() != ctx.block_size / 8) {
    return ErrorStatus::kFailure;
  }

  ctx.iv = std::vector<std::uint8_t>(iv_in.begin(), iv_in.end());

  return ErrorStatus::kSuccess;
}
ErrorStatus CTXController::SetMode(ModeContext& ctx, CipherMode mode) noexcept {
  if (!ctx.IsValid()) {
    return ErrorStatus::kFailure;
  }

  ctx.mode = mode;

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode