#pragma once
#include <memory>
#include <span>
#include <vector>
#include <string>

#include "encryption/interfaces.h"

namespace bedrock::cipher::op_mode {

enum class CipherMode { kEncrypt, kDecrypt };

class ModeContext : public BlockCipherCTX {
 public:
  ModeContext(
      const std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm>& impl,
      std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv,
      CipherMode mode_in, std::uint32_t m_bits = 64,
      bool use_openssl = true) noexcept;
  ~ModeContext() override;

  ErrorStatus EVPInit(const std::string& algorithm_name) noexcept;
  ErrorStatus SetKey(
      const std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm>& impl,
      std::span<const std::uint8_t> key_in) noexcept;
  ErrorStatus SetIV(
      const std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm>& impl,
      std::span<const std::uint8_t> iv_in) noexcept;
  ErrorStatus SetMode(CipherMode mode, bool padding = false) noexcept;

  std::vector<std::uint8_t> iv;
  CipherMode mode = CipherMode::kEncrypt;
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
      ModeContext& ctx, std::span<const std::uint8_t> input,
      std::span<std::uint8_t> output, bool final = true) = 0;

  std::string algorithm_name;
};

std::shared_ptr<OperationMode> PickImpl(const std::string& mode,
                                        bool use_openssl = true);

};  // namespace bedrock::cipher::op_mode
