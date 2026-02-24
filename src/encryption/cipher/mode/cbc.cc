#include "encryption/cipher/mode/cbc.h"

#include <openssl/evp.h>

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

  if (ctx.mode == bedrock::cipher::op_mode::CipherMode::Encrypt) {
    std::copy(input.begin(), input.end(), ctx.buffer.begin());
    util::XorInplace(ctx.buffer, ctx.prev_vector);
    impl->Encrypt(ctx, ctx.buffer, ctx.prev_vector);
    ctx.buffer = ctx.prev_vector;
  } else {
    impl->Decrypt(ctx, input, ctx.buffer);
    util::XorInplace(ctx.buffer, ctx.prev_vector);
    std::copy(input.begin(), input.end(), ctx.prev_vector.begin());
  }

  std::copy(ctx.buffer.begin(), ctx.buffer.end(), output.begin());

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode