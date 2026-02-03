#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_

#include "encryption/interfaces.h"

#include <array>

namespace bedrock::cipher {

struct AESMatrix {
 public:
  constexpr AESMatrix() = default;
  constexpr AESMatrix(std::array<std::array<std::uint8_t, 4>, 4> value_)
      : value(value_) {}
  constexpr AESMatrix(
      std::initializer_list<std::initializer_list<std::uint8_t>> init);
  constexpr AESMatrix operator*(const std::uint8_t& scalar) const;
  friend constexpr AESMatrix operator*(std::uint8_t lhs,
                                       const AESMatrix& matrix);

  constexpr AESMatrix operator*(const AESMatrix& matrix) const;
  constexpr AESMatrix operator+(const AESMatrix& matrix) const;

  std::array<std::uint8_t, 4>& operator[](std::size_t row) {
    return value[row];
  }
  const std::array<std::uint8_t, 4>& operator[](std::size_t row) const {
    return value[row];
  }

  int rows = 4;
  int cols = 4;

  std::array<std::array<std::uint8_t, 4>, 4> value = {};
};

class AES final : public BlockCipherAlgorithm {
 public:
  AES(std::span<const std::uint8_t> key);
  virtual ~AES() final override;

  BlockCipherErrorStatus Encrypt(std::span<const std::uint8_t> block,
                                 std::span<std::uint8_t> out) final override;
  BlockCipherErrorStatus Decrypt(std::span<const std::uint8_t> block,
                                 std::span<std::uint8_t> out) final override;

  static void Encrypt(std::span<const std::array<std::uint8_t, 16>> round_keys,
                      std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) noexcept;
  static void Decrypt(std::span<const std::array<std::uint8_t, 16>> round_keys,
                      std::span<const std::uint8_t> block,
                      std::span<std::uint8_t> out) noexcept;

  static void KeyExpantion(
      std::span<const std::uint8_t> key,
      std::span<std::array<std::uint8_t, 16>> enc_round_keys,
      std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept;

  bool IsValid() const final override { return valid; }

  std::uint32_t GetKeySize() final override;
  std::uint32_t GetBlockSize() final override;

 private:
  bool valid = false;

  // unit is bit
  std::uint32_t key_size = 0;

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

}  // namespace bedrock::cipher

#endif
