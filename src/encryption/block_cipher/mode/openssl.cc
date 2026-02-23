#include "encryption/block_cipher/mode/openssl.h"

namespace bedrock::cipher::op_mode {

ErrorStatus OPENSSL::Process(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, const std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, bool final) {
  if (impl == nullptr || !ctx.IsValid() || ctx.evp_ctx == nullptr ||
      ctx.evp_cipher == nullptr) {
    return ErrorStatus::kFailure;
  }
  if (ctx.padding && (input.size() > ctx.block_size / 8 ||
                      output.size() < ctx.block_size / 8 + input.size())) {
    return ErrorStatus::kFailure;
  } else if (!ctx.padding && (input.size() != ctx.block_size / 8 ||
                              output.size() != ctx.block_size / 8)) {
    return ErrorStatus::kFailure;
  }

  std::size_t written_size = 0;
  int err = 0;
  int out_len = 0;
  if (ctx.mode == bedrock::cipher::op_mode::CipherMode::Encrypt) {
    err = ::EVP_EncryptUpdate(ctx.evp_ctx, output.data(), &out_len,
                              input.data(), input.size());
  } else {
    err = ::EVP_DecryptUpdate(ctx.evp_ctx, output.data(), &out_len,
                              input.data(), input.size());
  }
  if (err == 0) {
    return ErrorStatus::kFailure;
  }
  written_size += out_len;

  if (!ctx.padding) {
    return ErrorStatus::kSuccess;
  }

  if (ctx.mode == bedrock::cipher::op_mode::CipherMode::Encrypt && final) {
    err = ::EVP_EncryptFinal_ex(ctx.evp_ctx, output.data() + written_size,
                                &out_len);
  } else if (ctx.mode == bedrock::cipher::op_mode::CipherMode::Decrypt &&
             final) {
    err = ::EVP_DecryptFinal_ex(ctx.evp_ctx, output.data() + written_size,
                                &out_len);
  }
  if (err == 0) {
    return ErrorStatus::kFailure;
  }
  written_size += out_len;

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode