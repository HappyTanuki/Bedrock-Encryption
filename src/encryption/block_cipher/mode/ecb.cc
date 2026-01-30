#include "encryption/block_cipher/mode/ecb.h"

namespace bedrock::cipher::op_mode {

BlockCipherErrorStatus ECB::Process(const std::span<const std::uint8_t> input,
                                    std::span<std::uint8_t> output) {
  std::uint32_t block_size = cipher->GetBlockSize() / 8;
  if (!cipher->IsValid() || input.size() != block_size ||
      output.size() != block_size) {
    return BlockCipherErrorStatus::kFailure;
  }

  if (this->mode == CipherMode::Encrypt) {
    this->cipher->Encrypt(input, output);
  } else {
    this->cipher->Decrypt(input, output);
  }

  return BlockCipherErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode