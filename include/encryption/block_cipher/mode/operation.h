#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_

#include <memory>
#include <span>

#include "encryption/interfaces.h"

namespace bedrock::cipher::op_mode {

enum class CipherMode { Encrypt, Decrypt };

// 운영 모드 인터페이스
class OperationMode : public Validatable {
 public:
  OperationMode(std::unique_ptr<BlockCipherAlgorithm> algorithm,
                const std::span<const std::byte> IV = {})
      : cipher(std::move(algorithm)), prev_vector(IV.begin(), IV.end()) {
    buffer.resize(IV.size());
  }
  virtual ~OperationMode() override;

  virtual BlockCipherErrorStatus Process(const std::span<const std::byte> input,
                                         std::span<std::byte> output) = 0;

  OperationMode& operator<<(const CipherMode& _mode) {
    this->mode = _mode;
    return *this;
  }

  void SetIV(const std::span<const std::byte> IV) {
    prev_vector = std::vector<std::byte>(IV.begin(), IV.end());
    buffer.resize(IV.size());
  }

 protected:
  std::unique_ptr<BlockCipherAlgorithm> cipher;

  std::vector<std::byte> prev_vector;
  std::vector<std::byte> buffer;

  CipherMode mode = CipherMode::Encrypt;
};

};  // namespace bedrock::cipher::op_mode

#endif
