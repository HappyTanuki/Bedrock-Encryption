#include "encryption/block_cipher/mode/gcm.h"

namespace bedrock::cipher::op_mode {

ErrorStatus GCM::Process(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    ModeContext& ctx, const std::span<const std::uint8_t> input,
    std::span<std::uint8_t> output) {
  return ErrorStatus::kSuccess;
}

bool GCM::IsValid() const { return true; }

}  // namespace bedrock::cipher::op_mode