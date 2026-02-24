#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_OPERATION_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_CIPHER_MODE_OPERATION_H_

#include <memory>
#include <span>
#include <vector>

#include "encryption/interfaces.h"

namespace bedrock::cipher::op_mode {

enum class CipherMode { Encrypt, Decrypt };

class ModeContext : public BlockCipherCTX {
 public:
  ModeContext(std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
              std::span<const std::uint8_t> key,
              std::span<const std::uint8_t> iv, CipherMode mode,
              std::uint32_t m_bits = 64, bool use_openssl = true) noexcept;
  virtual ~ModeContext() override;

  ErrorStatus EVPInit(const std::string algorithm_name) noexcept;
  ErrorStatus SetKey(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      std::span<const std::uint8_t> key_in) noexcept;
  ErrorStatus SetIV(std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
                    std::span<const std::uint8_t> iv_in) noexcept;
  ErrorStatus SetMode(CipherMode mode, bool padding = false) noexcept;

  std::vector<std::uint8_t> iv;
  CipherMode mode;
  std::uint32_t m_bits = 64;
  bool padding = false;
  std::vector<std::uint8_t> prev_vector;
  std::vector<std::uint8_t> buffer;
};

// 운영 모드 인터페이스
class OperationMode {
 public:
  virtual ~OperationMode();

  virtual ErrorStatus Process(
      std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
      ModeContext& ctx, const std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) = 0;

  std::string algorithm_name = "";
};

class ImplPicker {
 public:
  static std::shared_ptr<OperationMode> PickImpl(std::string mode,
                                                 bool use_openssl = false);

 private:
  ImplPicker();
};

};  // namespace bedrock::cipher::op_mode

#endif
