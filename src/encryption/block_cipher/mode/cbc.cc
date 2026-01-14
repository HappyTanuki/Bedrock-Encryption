#include "encryption/block_cipher/mode/cbc.h"

#include "encryption/util/helper.h"

namespace bedrock::cipher::op_mode {

BlockCipherErrorStatus CBC::Process(const std::span<const std::byte> input,
                                    std::span<std::byte> output) {
  std::uint32_t block_size = cipher->GetBlockSize() / 8;
  if (!cipher->IsValid() || input.size() != block_size ||
      output.size() != block_size) {
    return BlockCipherErrorStatus::kFailure;
  }

  if (this->mode == bedrock::cipher::op_mode::CipherMode::Encrypt) {
    std::copy(input.begin(), input.end(), buffer.begin());
    util::XorInplace(buffer, this->prev_vector);
    this->cipher->Encrypt(buffer, prev_vector);
    buffer = this->prev_vector;
  } else {
    this->cipher->Decrypt(input, buffer);
    util::XorInplace(buffer, this->prev_vector);
    std::copy(input.begin(), input.end(), this->prev_vector.begin());
  }

  std::copy(buffer.begin(), buffer.end(), output.begin());

  return BlockCipherErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode