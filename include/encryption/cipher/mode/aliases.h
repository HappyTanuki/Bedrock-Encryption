#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_ALIASES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "../aes.h"
#include "encryption/cipher/mode/operation.h"

namespace bedrock::cipher {

// AES-CBC 모드 편의성 단축
class AES_CBC {
 public:
  AES_CBC(const std::span<const std::uint8_t> key,
          const std::span<const std::uint8_t> iv)
      : impl(AESPicker::PickImpl()),
        mode_impl(op_mode::ImplPicker::PickImpl("CBC")),
        ctx(impl, key, iv, op_mode::CipherMode::Encrypt, 0) {
    ctx.EVPInit(impl->GetAlgorithmName() + std::string("-") +
                std::to_string(ctx.key_size) + "-" + mode_impl->algorithm_name);
  }
  virtual ~AES_CBC();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl->Process(impl, ctx, input, output);
  }

  AES_CBC& operator<<(const op_mode::CipherMode& _mode) {
    ctx.SetMode(_mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl;
  std::shared_ptr<op_mode::OperationMode> mode_impl;
  op_mode::ModeContext ctx;
};

// AES-CTR 모드 편의성 단축
class AES_CTR {
 public:
  AES_CTR(const std::span<const std::uint8_t> key,
          const std::span<const std::uint8_t> iv)
      : impl(AESPicker::PickImpl()),
        mode_impl(op_mode::ImplPicker::PickImpl("CTR")),
        ctx(impl, key, iv, op_mode::CipherMode::Encrypt, 0) {
    ctx.EVPInit(impl->GetAlgorithmName() + std::string("-") +
                std::to_string(ctx.key_size) + "-" + mode_impl->algorithm_name);
  }
  virtual ~AES_CTR();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl->Process(impl, ctx, input, output);
  }

  AES_CTR& operator<<(const op_mode::CipherMode& _mode) {
    ctx.SetMode(_mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl;
  std::shared_ptr<op_mode::OperationMode> mode_impl;
  op_mode::ModeContext ctx;
};

// AES-ECB 모드 편의성 단축
class AES_ECB {
 public:
  AES_ECB(const std::span<const std::uint8_t> key)
      : impl(AESPicker::PickImpl()),
        mode_impl(op_mode::ImplPicker::PickImpl("ECB")),
        ctx(impl, key, {}, op_mode::CipherMode::Encrypt, 0) {
    ctx.EVPInit(impl->GetAlgorithmName() + std::string("-") +
                std::to_string(ctx.key_size) + "-" + mode_impl->algorithm_name);
  }
  virtual ~AES_ECB();

  ErrorStatus Process(const std::span<const std::uint8_t> input,
                      std::span<std::uint8_t> output) {
    return mode_impl->Process(impl, ctx, input, output);
  }

  AES_ECB& operator<<(const op_mode::CipherMode& _mode) {
    ctx.SetMode(_mode);
    return *this;
  }

 private:
  std::shared_ptr<BlockCipherAlgorithm> impl;
  std::shared_ptr<op_mode::OperationMode> mode_impl;
  op_mode::ModeContext ctx;
};

}  // namespace bedrock::cipher

#endif
