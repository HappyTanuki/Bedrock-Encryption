#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_

#include <memory>
#include <span>

#include "encryption/interfaces.h"

namespace bedrock::cipher::op_mode {

enum class CipherMode { Encrypt, Decrypt };

// 운영 모드 인터페이스
template <std::uint32_t Blocksize = 16>
class OperationMode : public Validatable {
 public:
  OperationMode(std::unique_ptr<BlockCipherAlgorithm<Blocksize>> algorithm,
                const std::span<const std::uint8_t> IV = {})
      : cipher(std::move(algorithm)), prev_vector(IV.begin(), IV.end()) {
    buffer.resize(IV.size());
  }
  virtual ~OperationMode() override = default;

  virtual ErrorStatus Process(const std::span<const std::uint8_t> input,
                              std::span<std::uint8_t> output) = 0;

  OperationMode& operator<<(const CipherMode& _mode) {
    this->mode = _mode;
    return *this;
  }

  void SetIV(const std::span<const std::uint8_t> IV) {
    prev_vector = std::vector<std::uint8_t>(IV.begin(), IV.end());
    buffer.resize(IV.size());
  }

 protected:
  std::unique_ptr<BlockCipherAlgorithm<Blocksize>> cipher;

  std::vector<std::uint8_t> prev_vector;
  std::vector<std::uint8_t> buffer;

  CipherMode mode = CipherMode::Encrypt;
};

};  // namespace bedrock::cipher::op_mode

#endif
