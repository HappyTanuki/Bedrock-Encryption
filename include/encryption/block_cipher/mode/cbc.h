#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CBC_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_CBC_H_

#include <cmath>
#include <cstring>

#include "encryption/util/helper.h"
#include "operation.h"

namespace bedrock::cipher::op_mode {

// CBC 운영 모드
template <std::uint32_t Blocksize = 16>
class CBC : public OperationMode<Blocksize> {
 public:
  using OperationMode<Blocksize>::OperationMode;

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) final override;

  bool IsValid() const final override { return true; }
};

template <std::uint32_t Blocksize>
ErrorStatus CBC<Blocksize>::Process(const std::span<const std::uint8_t> input,
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

};  // namespace bedrock::cipher::op_mode

#endif
