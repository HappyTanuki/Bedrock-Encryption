#pragma once
#include <memory>

#include "../aes.h"
#include "encryption/cipher/mode/operation.h"

namespace bedrock::cipher {

// AES-CBC 모드 편의성 단축 (deprecated)
class AesCbc {
 public:
  AesCbc(const std::span<const std::uint8_t> key,
         const std::span<const std::uint8_t> iv)
      : impl_(AESPicker::PickImpl()),
        mode_impl_(op_mode::PickImpl("CBC")),
        ctx_(impl_, key, iv, op_mode::CipherMode::kEncrypt, 0) {
    ctx_.EVPInit(impl_->GetAlgorithmName() + std::string("-") +
                 std::to_string(ctx_.key_size) + "-" +
                 mode_impl_->algorithm_name);
  }
  virtual ~AesCbc();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl_->Process(impl_, ctx_, input, output);
  }

  AesCbc& operator<<(const op_mode::CipherMode& mode) {
    ctx_.SetMode(mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl_;
  std::shared_ptr<op_mode::OperationMode> mode_impl_;
  op_mode::ModeContext ctx_;
};

// AES-CTR 모드 편의성 단축
class AesCtr {
 public:
  AesCtr(const std::span<const std::uint8_t> key,
         const std::span<const std::uint8_t> iv)
      : impl_(AESPicker::PickImpl()),
        mode_impl_(op_mode::PickImpl("CTR")),
        ctx_(impl_, key, iv, op_mode::CipherMode::kEncrypt, 0) {
    ctx_.EVPInit(impl_->GetAlgorithmName() + std::string("-") +
                 std::to_string(ctx_.key_size) + "-" +
                 mode_impl_->algorithm_name);
  }
  virtual ~AesCtr();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl_->Process(impl_, ctx_, input, output);
  }

  AesCtr& operator<<(const op_mode::CipherMode& mode) {
    ctx_.SetMode(mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl_;
  std::shared_ptr<op_mode::OperationMode> mode_impl_;
  op_mode::ModeContext ctx_;
};

// AES-ECB 모드 편의성 단축
class AesEcb {
 public:
  explicit AesEcb(const std::span<const std::uint8_t> key)
      : impl_(AESPicker::PickImpl()),
        mode_impl_(op_mode::PickImpl("ECB")),
        ctx_(impl_, key, {}, op_mode::CipherMode::kEncrypt, 0) {
    ctx_.EVPInit(impl_->GetAlgorithmName() + std::string("-") +
                 std::to_string(ctx_.key_size) + "-" +
                 mode_impl_->algorithm_name);
  }
  virtual ~AesEcb();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl_->Process(impl_, ctx_, input, output);
  }

  AesEcb& operator<<(const op_mode::CipherMode& mode) {
    ctx_.SetMode(mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl_;
  std::shared_ptr<op_mode::OperationMode> mode_impl_;
  op_mode::ModeContext ctx_;
};

}  // namespace bedrock::cipher
