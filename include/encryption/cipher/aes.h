#pragma once
#include <array>
#include <memory>

#include "encryption/interfaces.h"

namespace bedrock::cipher {

class AESImpl : public BlockCipherAlgorithm {
 public:
  ~AESImpl() noexcept override;

  ErrorStatus Encrypt(BlockCipherCTX& key, std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) const noexcept final;
  ErrorStatus Decrypt(BlockCipherCTX& key, std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) const noexcept final;

  [[nodiscard]] [[nodiscard]] std::uint32_t GetBlockSize()
      const noexcept final {
    return 128;
  }

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override = 0;

  [[nodiscard]] [[nodiscard]] const char* GetAlgorithmName()
      const noexcept override {
    return "AES";
  }

 protected:
  virtual void EncryptImpl(BlockCipherCTX& ctx,
                           std::span<const std::uint8_t> block,
                           std::span<std::uint8_t> out) const noexcept = 0;
  virtual void DecryptImpl(BlockCipherCTX& ctx,
                           std::span<const std::uint8_t> block,
                           std::span<std::uint8_t> out) const noexcept = 0;

  bool valid_ = false;
};

class AesNi : public AESImpl {
 public:
  ~AesNi() override;

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override;

 protected:
  void EncryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
  void DecryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
};

class AesSoft : public AESImpl {
 public:
  ~AesSoft() override;

  ErrorStatus KeyExpantion(std::span<const std::uint8_t> key,
                           BlockCipherCTX& ctx) const noexcept override;

 protected:
  void EncryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;
  void DecryptImpl(BlockCipherCTX& ctx, std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) const noexcept override;

 private:
  static std::uint8_t SBox(std::uint8_t x);
  static std::uint8_t InvSBox(std::uint8_t x);

  //static std::array<std::uint8_t, 14> Rcon_memo;
  //static int Rcon_memo_index;
  static constexpr std::array<std::uint8_t, 11> kRcon = {
      0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

  inline static std::uint32_t SubWord(std::uint32_t word) noexcept;
  inline static std::uint32_t RotWord(std::uint32_t word) noexcept;
  // constexpr static std::uint8_t Rcon(const std::uint32_t i) noexcept;

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
  static ErrorStatus Create(const std::shared_ptr<BlockCipherAlgorithm>& impl,
                            std::span<const std::uint8_t> key,
                            BlockCipherCTX& out) noexcept;
  static ErrorStatus SetKey(const std::shared_ptr<BlockCipherAlgorithm>& impl,
                            BlockCipherCTX& ctx,
                            std::span<const std::uint8_t> key_in) noexcept;

 private:
  AESCTXController() = delete;
};

}  // namespace bedrock::cipher
