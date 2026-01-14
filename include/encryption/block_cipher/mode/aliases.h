#ifndef FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#define FILE_ENCRYPT_UTIL_INCLUDEALGORITHM_BLOCK_CIPHER_MODE_ALIASES_H_
#include <memory>

#include "../aes.h"
#include "cbc.h"
#include "ctr.h"
#include "ecb.h"

namespace bedrock::cipher {

// AES-CBC 모드 별칭
class AES_CBC : public op_mode::CBC {
 public:
  AES_CBC(const std::span<const std::byte> key,
          const std::span<const std::byte> iv)
      : op_mode::CBC(std::make_unique<AES>(key), iv) {}
  virtual ~AES_CBC() override;
};

// AES-CTR 모드 별칭
class AES_CTR : public op_mode::CTR {
 public:
  AES_CTR(const std::span<const std::byte> key,
          const std::span<const std::byte> iv)
      : op_mode::CTR(std::make_unique<AES>(key), iv) {}
  virtual ~AES_CTR() override;
};

// AES-ECB 모드 별칭
class AES_ECB : public op_mode::ECB {
 public:
  AES_ECB(const std::span<const std::byte> key)
      : op_mode::ECB(std::make_unique<AES>(key)) {}
  virtual ~AES_ECB() override;
};

}  // namespace bedrock::cipher

#endif
