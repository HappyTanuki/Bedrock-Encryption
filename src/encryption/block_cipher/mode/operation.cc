#include "encryption/block_cipher/mode/operation.h"

#include <openssl/evp.h>

#include "encryption/block_cipher/aes.h"
#include "encryption/block_cipher/mode/cbc.h"
#include "encryption/block_cipher/mode/ctr.h"
#include "encryption/block_cipher/mode/ecb.h"
#include "encryption/block_cipher/mode/openssl.h"

namespace bedrock::cipher::op_mode {

ModeContext::ModeContext(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    std::span<const std::uint8_t> key, std::span<const std::uint8_t> iv_in,
    CipherMode mode, std::uint32_t m_bits, bool use_openssl) noexcept {
  if (impl == nullptr) {
    return;
  }

  if (use_openssl) {
    evp_ctx = ::EVP_CIPHER_CTX_new();
  }

  if (AESCTXController::Create(impl, key, *this) != ErrorStatus::kSuccess) {
    return;
  }

  iv = std::vector<std::uint8_t>(iv_in.begin(), iv_in.end());
  iv.resize(block_size / 8);
  mode = mode;
  m_bits = m_bits;
  prev_vector = std::vector<std::uint8_t>(iv.begin(), iv.end());
  prev_vector.resize(block_size / 8);
  buffer.resize(block_size / 8);

  if (m_bits != 0) {
    std::uint32_t block_bytes = block_size / 8;
    std::uint32_t counter_bytes = (m_bits + 7) / 8;

    for (std::uint32_t i = block_bytes - 1; i > block_bytes - counter_bytes;
         i--) {
      prev_vector[i] = static_cast<std::uint8_t>(0x00);
      m_bits -= 8;
    }
    prev_vector[block_bytes - counter_bytes] &=
        static_cast<std::uint8_t>(0xFF << m_bits);
  }

  if (evp_cipher != nullptr) {
    valid = true;
  }

  return;
}
ErrorStatus ModeContext::EVPInit(const std::string algorithm_name) noexcept {
  if (algorithm_name.empty()) {
    return ErrorStatus::kFailure;
  }

  evp_cipher = ::EVP_CIPHER_fetch(nullptr, algorithm_name.c_str(), nullptr);
  if (evp_cipher == nullptr) {
    return ErrorStatus::kFailure;
  }
  if (SetMode(mode) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }
  valid = true;

  return ErrorStatus::kSuccess;
}
ErrorStatus ModeContext::SetKey(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    std::span<const std::uint8_t> key_in) noexcept {
  if (impl == nullptr || !IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (AESCTXController::SetKey(impl, *this, key_in) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }
  if (SetMode(mode) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  return ErrorStatus::kSuccess;
}
ErrorStatus ModeContext::SetIV(
    std::shared_ptr<bedrock::cipher::BlockCipherAlgorithm> impl,
    std::span<const std::uint8_t> iv_in) noexcept {
  if (impl == nullptr || !IsValid()) {
    return ErrorStatus::kFailure;
  }

  if (iv_in.size() != block_size / 8) {
    return ErrorStatus::kFailure;
  }

  iv = std::vector<std::uint8_t>(iv_in.begin(), iv_in.end());

  if (SetMode(mode) != ErrorStatus::kSuccess) {
    return ErrorStatus::kFailure;
  }

  return ErrorStatus::kSuccess;
}
ErrorStatus ModeContext::SetMode(CipherMode mode, bool padding) noexcept {
  if (!IsValid()) {
    return ErrorStatus::kFailure;
  }

  EVP_CIPHER_CTX_cleanup(evp_ctx);

  if (mode == bedrock::cipher::op_mode::CipherMode::Encrypt) {
    ::EVP_EncryptInit_ex2(evp_ctx, evp_cipher, enc_round_keys[0].data(),
                          iv.data(), nullptr);
  } else {
    ::EVP_DecryptInit_ex2(evp_ctx, evp_cipher, enc_round_keys[0].data(),
                          iv.data(), nullptr);
  }
  if (!padding) {
    OSSL_PARAM padding_param[2] = {OSSL_PARAM_construct_uint("padding", 0),
                                   OSSL_PARAM_END};

    ::EVP_CIPHER_CTX_set_params(evp_ctx, padding_param);
  }
  this->padding = padding;
  this->mode = mode;

  return ErrorStatus::kSuccess;
}

ModeContext::~ModeContext() = default;
OperationMode::~OperationMode() = default;

std::shared_ptr<OperationMode> ImplPicker::PickImpl(std::string mode,
                                                    bool use_openssl) {
  std::shared_ptr<OperationMode> impl;

  if (mode == "CBC") {
    impl = std::make_shared<CBC>();
  } else if (mode == "CTR") {
    impl = std::make_shared<CTR>();
  } else if (mode == "ECB") {
    impl = std::make_shared<ECB>();
  } else if (use_openssl) {
    impl = std::make_shared<OPENSSL>();
    impl->algorithm_name = mode;
  } else {
    return nullptr;
  }

  return impl;
}

}  // namespace bedrock::cipher::op_mode