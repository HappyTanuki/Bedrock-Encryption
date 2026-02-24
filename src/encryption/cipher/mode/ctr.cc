#include "encryption/cipher/mode/ctr.h"

#include "encryption/util/helper.h"

namespace bedrock::cipher::op_mode {

ErrorStatus CTR::Process(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, const std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output, bool final) {
  if (impl == nullptr || !ctx.IsValid() || input.size() != ctx.block_size / 8 ||
      output.size() != ctx.block_size / 8 || ctx.m_bits == 0) {
    return ErrorStatus::kFailure;
  }

  impl->Encrypt(ctx, ctx.prev_vector, ctx.buffer);
  bedrock::util::StandardIncrement(ctx.prev_vector, ctx.m_bits);

  std::copy(ctx.buffer.begin(), ctx.buffer.end(), output.begin());
  bedrock::util::XorInplace(output, input);

  return ErrorStatus::kSuccess;
}
}  // namespace bedrock::cipher::op_mode