#include "encryption/cipher/mode/cbc.h"

#include <algorithm>

#include "encryption/util/helper.h"

namespace bedrock::cipher::op_mode {

ErrorStatus CBC::Process(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, const std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, bool final) {
  if (impl == nullptr || !ctx.IsValid() || input.size() != ctx.block_size / 8 ||
      output.size() != ctx.block_size / 8) {
    return ErrorStatus::kFailure;
  }

  if (ctx.mode == bedrock::cipher::op_mode::CipherMode::kEncrypt) {
    std::ranges::copy(input, ctx.buffer.begin());
    util::XorInplace(ctx.buffer, ctx.prev_vector);
    impl->Encrypt(ctx, ctx.buffer, ctx.prev_vector);
    ctx.buffer = ctx.prev_vector;
  } else {
    impl->Decrypt(ctx, input, ctx.buffer);
    util::XorInplace(ctx.buffer, ctx.prev_vector);
    std::ranges::copy(input, ctx.prev_vector.begin());
  }

  std::ranges::copy(ctx.buffer, output.begin());

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode