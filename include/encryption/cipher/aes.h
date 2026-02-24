#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_

#include <array>
#include <memory>

#include "encryption/interfaces.h"

namespace bedrock::cipher {

class AESImpl : public BlockCipherAlgorithm {
 public:
  virtual ~AESImpl() noexcept override;

  ErrorStatus Encrypt(
      BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
      std::span<std::uint8_t> out) const noexcept final override;
  ErrorStatus Decrypt(
      BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
      std::span<std::uint8_t> out) const noexcept final override;

  std::uint32_t GetBlockSize() const noexcept final override { return 128; }

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override = 0;

  const char* GetAlgorithmName() const noexcept override { return "AES"; }

 protected:
  virtual void EncryptImpl(BlockCipherCTX& ctx,
                           std::span<const std::uint8_t> block,
                           std::span<std::uint8_t> out) const noexcept = 0;
  virtual void DecryptImpl(BlockCipherCTX& ctx,
                           std::span<const std::uint8_t> block,
                           std::span<std::uint8_t> out) const noexcept = 0;

  bool valid = false;
};

class AES_NI : public AESImpl {
 public:
  virtual ~AES_NI() override;

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override;

 protected:
  void EncryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
  void DecryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
};

class AES_SOFT : public AESImpl {
 public:
  virtual ~AES_SOFT() override;

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override;

 protected:
  void EncryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
  void DecryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;

 private:
  static std::uint8_t S_box(std::uint8_t x);
  static std::uint8_t Inv_S_box(std::uint8_t x);

  static std::array<std::uint8_t, 14> Rcon_memo;
  static int Rcon_memo_index;

  inline static std::uint32_t SubWord(const std::uint32_t word) noexcept;
  inline static std::uint32_t RotWord(const std::uint32_t word) noexcept;
  constexpr static std::uint8_t Rcon(const std::uint32_t i) noexcept;

  constexpr static void AddRoundKey(
      std::span<std::uint8_t> state,
      std::span<const std::uint8_t> round_key) noexcept;
  inline static void InvMixColumns(std::span<std::uint8_t> state) noexcept;
  inline static void InvShiftRows(std::span<std::uint8_t> state) noexcept;
  constexpr static void InvSubBytes(std::span<std::uint8_t> state) noexcept;
  constexpr static void MixColumns(std::span<std::uint8_t> state) noexcept;
  inline static void ShiftRows(std::span<std::uint8_t> state) noexcept;
  constexpr static void SubBytes(std::span<std::uint8_t> state) noexcept;
};

class AESPicker {
 public:
  static std::shared_ptr<AESImpl> PickImpl();

 private:
  AESPicker();
};

class AESCTXController {
 public:
  static ErrorStatus Create(std::shared_ptr<BlockCipherAlgorithm> impl,
                            std::span<const std::uint8_t> key,
                            BlockCipherCTX& out) noexcept;
  static ErrorStatus SetKey(std::shared_ptr<BlockCipherAlgorithm> impl,
                            BlockCipherCTX& ctx,
                            std::span<const std::uint8_t> key_in) noexcept;

 private:
  AESCTXController();
};

}  // namespace bedrock::cipher

#endif
