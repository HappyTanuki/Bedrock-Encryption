#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_

#include <array>
#include <memory>

#include "encryption/interfaces.h"

namespace bedrock::cipher {

class AESImpl : public BlockCipherAlgorithm<16> {
 public:
  virtual ~AESImpl() noexcept override;

  ErrorStatus Encrypt(std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) noexcept final override;
  ErrorStatus Decrypt(std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) noexcept final override;

  ErrorStatus SetKey(const BlockCipherKey<16>& key_in) noexcept final override;
  ErrorStatus SetKey(
      std::span<const std::uint8_t> key_in) noexcept final override;
  void GetKey(BlockCipherKey<16>& key_out) noexcept final override {
    key_out = key;
  }

  bool IsValid() const noexcept final override { return valid; }

  std::uint32_t GetKeySize() const noexcept final override { return key.size; }
  std::uint32_t GetBlockSize() const noexcept final override { return 128; }

 protected:
  virtual void EncryptImpl(
      std::span<const std::array<std::uint8_t, 16>> round_keys,
      std::span<const std::uint8_t> block,
      std::span<std::uint8_t> out) noexcept = 0;
  virtual void DecryptImpl(
      std::span<const std::array<std::uint8_t, 16>> round_keys,
      std::span<const std::uint8_t> block,
      std::span<std::uint8_t> out) noexcept = 0;

  virtual void KeyExpantion(
      std::span<const std::uint8_t> key,
      std::span<std::array<std::uint8_t, 16>> enc_round_keys,
      std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept = 0;

  bool valid = false;
};

class AES_NI : public AESImpl {
 public:
  virtual ~AES_NI() override;

 protected:
  void EncryptImpl(std::span<const std::array<std::uint8_t, 16>> round_keys,
                   std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) noexcept override;
  void DecryptImpl(std::span<const std::array<std::uint8_t, 16>> round_keys,
                   std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) noexcept override;

  void KeyExpantion(
      std::span<const std::uint8_t> key,
      std::span<std::array<std::uint8_t, 16>> enc_round_keys,
      std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept override;

 private:
  static std::array<std::uint8_t, 14> Rcon_memo;
  static int Rcon_memo_index;

  static std::uint8_t S_box(std::uint8_t x);
  static std::uint8_t Inv_S_box(std::uint8_t x);

  inline static std::uint32_t SubWord(const std::uint32_t word) noexcept;
  inline static std::uint32_t RotWord(const std::uint32_t word) noexcept;
  constexpr static std::uint8_t Rcon(const std::uint32_t i) noexcept;
};

class AES_SOFT : public AESImpl {
 public:
  virtual ~AES_SOFT() override;

 protected:
  void EncryptImpl(std::span<const std::array<std::uint8_t, 16>> round_keys,
                   std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) noexcept override;
  void DecryptImpl(std::span<const std::array<std::uint8_t, 16>> round_keys,
                   std::span<const std::uint8_t> block,
                   std::span<std::uint8_t> out) noexcept override;

  void KeyExpantion(
      std::span<const std::uint8_t> key,
      std::span<std::array<std::uint8_t, 16>> enc_round_keys,
      std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept override;

 private:
  alignas(16) std::array<std::array<std::uint8_t, 16>, 15> enc_round_keys;
  alignas(16) std::array<std::array<std::uint8_t, 16>, 15> dec_round_keys;
  alignas(16) std::array<std::uint8_t, 16> state;

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
  static std::unique_ptr<AESImpl> PickImpl(std::span<const std::uint8_t> key);

 private:
  AESPicker();
};

}  // namespace bedrock::cipher

#endif
