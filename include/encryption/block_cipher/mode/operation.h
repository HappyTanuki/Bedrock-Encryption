#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_OPERATION_H_

#include <memory>
#include <span>
#include <vector>

#include "encryption/interfaces.h"

namespace bedrock::cipher::op_mode {

enum class CipherMode { Encrypt, Decrypt };

class ModeContext : public BlockCipherCTX {
 public:
  virtual ~ModeContext() override;

  std::vector<std::uint8_t> iv;
  CipherMode mode;
  std::uint32_t m_bits = 64;
  std::vector<std::uint8_t> prev_vector;
  std::vector<std::uint8_t> buffer;
};

// 운영 모드 인터페이스
class OperationMode : public Validatable {
 public:
  virtual ~OperationMode() override;

  virtual ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output) = 0;
};

class ImplPicker {
 public:
  static std::shared_ptr<OperationMode> PickImpl(std::string mode);

 private:
  ImplPicker();
};

class CTXController {
 public:
  static ErrorStatus Create(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& out, std::span<const std::uint8_t> key,
      std::span<const std::uint8_t> iv, CipherMode mode,
      std::uint32_t m_bits = 64) noexcept;
  static ErrorStatus SetKey(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, std::span<const std::uint8_t> key_in) noexcept;
  static ErrorStatus SetIV(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, std::span<const std::uint8_t> iv_in) noexcept;
  static ErrorStatus SetMode(ModeContext& ctx, CipherMode mode) noexcept;

 private:
  CTXController();
};

};  // namespace bedrock::cipher::op_mode

#endif
