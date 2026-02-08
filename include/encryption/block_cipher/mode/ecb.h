#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ECB_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ECB_H_

#include "operation.h"

namespace bedrock::cipher::op_mode {

template <std::uint32_t Blocksize = 16>
class ECB : public OperationMode<Blocksize> {
 public:
  using OperationMode<Blocksize>::OperationMode;

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) final override;

  bool IsValid() const final override { return true; }
};

template <std::uint32_t BlockSize>
ErrorStatus ECB<BlockSize>::Process(const std::span<const std::uint8_t> input,
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

#endif
