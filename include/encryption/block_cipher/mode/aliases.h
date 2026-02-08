#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "../aes.h"
#include "cbc.h"
#include "ctr.h"
#include "ecb.h"

namespace bedrock::cipher {

// AES-CBC 모드 별칭
class AES_CBC : public op_mode::CBC<16> {
 public:
  AES_CBC(const std::span<const std::uint8_t> key,
          const std::span<const std::uint8_t> iv)
      : op_mode::CBC<16>(AESPicker::PickImpl(key), iv) {}
  virtual ~AES_CBC() override;
};

// AES-CTR 모드 별칭
class AES_CTR : public op_mode::CTR<16> {
 public:
  AES_CTR(const std::span<const std::uint8_t> key,
          const std::span<const std::uint8_t> iv)
      : op_mode::CTR<16>(AESPicker::PickImpl(key), iv) {}
  virtual ~AES_CTR() override;
};

// AES-ECB 모드 별칭
class AES_ECB : public op_mode::ECB<16> {
 public:
  AES_ECB(const std::span<const std::uint8_t> key)
      : op_mode::ECB<16>(AESPicker::PickImpl(key)) {}
  virtual ~AES_ECB() override;
};

}  // namespace bedrock::cipher

#endif
