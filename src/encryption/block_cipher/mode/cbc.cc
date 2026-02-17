#include "encryption/block_cipher/mode/cbc.h"

#include "encryption/util/helper.h"

namespace bedrock::cipher::op_mode {

ErrorStatus CBC::Process(const std::span<const std::uint8_t> input,
                         std::span<std::uint8_t> output) {
  std::uint32_t block_size = this->cipher->GetBlockSize() / 8;
  if (!this->cipher->IsValid() || input.size() != block_size ||
      output.size() != block_size) {
    return ErrorStatus::kFailure;
  }

  if (this->mode == bedrock::cipher::op_mode::CipherMode::Encrypt) {
    std::copy(input.begin(), input.end(), this->buffer.begin());
    util::XorInplace(this->buffer, this->prev_vector);
    this->cipher->Encrypt(this->buffer, this->prev_vector);
    this->buffer = this->prev_vector;
  } else {
    this->cipher->Decrypt(input, this->buffer);
    util::XorInplace(this->buffer, this->prev_vector);
    std::copy(input.begin(), input.end(), this->prev_vector.begin());
  }

  std::copy(this->buffer.begin(), this->buffer.end(), output.begin());

  return ErrorStatus::kSuccess;
}
}  // namespace bedrock::cipher::op_mode