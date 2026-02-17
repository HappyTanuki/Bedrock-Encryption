#include "encryption/block_cipher/mode/ecb.h"

namespace bedrock::cipher::op_mode {

ErrorStatus ECB::Process(const std::span<const std::uint8_t> input,
                         std::span<std::uint8_t> output) {
  std::uint32_t block_size = this->cipher->GetBlockSize() / 8;
  if (!this->cipher->IsValid() || input.size() != block_size ||
      output.size() != block_size) {
    return ErrorStatus::kFailure;
  }

  if (this->mode == CipherMode::Encrypt) {
    this->cipher->Encrypt(input, output);
  } else {
    this->cipher->Decrypt(input, output);
  }

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode