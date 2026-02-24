#include "encryption/cipher/mode/ecb.h"

namespace bedrock::cipher::op_mode {

ErrorStatus ECB::Process(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, const std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, bool final) {
  if (impl == nullptr || !ctx.IsValid() || input.size() != ctx.block_size / 8 ||
      output.size() != ctx.block_size / 8) {
    return ErrorStatus::kFailure;
  }

  if (ctx.mode == CipherMode::Encrypt) {
    impl->Encrypt(ctx, input, output);
  } else {
    impl->Decrypt(ctx, input, output);
  }

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode