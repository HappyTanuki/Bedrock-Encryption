#include "encryption/interfaces.h"

namespace bedrock::cipher {

BlockCipherAlgorithm::~BlockCipherAlgorithm() noexcept = default;

BlockCipherCTX::~BlockCipherCTX() {
  if (evp_ctx != nullptr) {
    ::EVP_CIPHER_CTX_free(evp_ctx);
    evp_ctx = nullptr;
  }
  if (evp_cipher != nullptr) {
    ::EVP_CIPHER_free(evp_cipher);
    evp_cipher = nullptr;
  }
}

};  // namespace bedrock::cipher