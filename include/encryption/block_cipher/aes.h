#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_BLOCK_CIPHER_AES_H_

#include "encryption/interfaces.h"

namespace bedrock::cipher {

struct AESMatrix {
 public:
  constexpr AESMatrix() = default;
  constexpr AESMatrix(std::array<std::array<std::byte, 4>, 4> value_)
      : value(value_) {}
  constexpr AESMatrix(
      std::initializer_list<std::initializer_list<std::byte>> init);
  constexpr AESMatrix(
      std::initializer_list<std::initializer_list<std::uint8_t>> init);
  constexpr AESMatrix operator*(const std::byte& scalar) const;
  friend constexpr AESMatrix operator*(std::byte lhs, const AESMatrix& matrix);

  constexpr AESMatrix operator*(const AESMatrix& matrix) const;
  constexpr AESMatrix operator+(const AESMatrix& matrix) const;

  std::array<std::byte, 4>& operator[](std::size_t row) { return value[row]; }
  const std::array<std::byte, 4>& operator[](std::size_t row) const {
    return value[row];
  }

  int rows = 4;
  int cols = 4;

  std::array<std::array<std::byte, 4>, 4> value = {};
};

class AES final : public BlockCipherAlgorithm {
 public:
  AES(const std::span<const std::byte> key);
  virtual ~AES() final override;

  BlockCipherErrorStatus Encrypt(const std::span<const std::byte> block,
                                 std::span<std::byte> out) final override;
  BlockCipherErrorStatus Decrypt(const std::span<const std::byte> block,
                                 std::span<std::byte> out) final override;

  static void Encrypt(
      const std::span<const std::array<std::byte, 4>> expanded_key,
      const std::span<const std::byte> block, std::span<std::byte> out,
      const bool intrinsics = true) noexcept;
  static void Decrypt(
      const std::span<const std::array<std::byte, 4>> expanded_key,
      const std::span<const std::byte> block, std::span<std::byte> out,
      const bool intrinsics = true) noexcept;

  static void KeyExpantion(const std::span<const std::byte> key,
                           std::span<std::array<std::byte, 4>> expanded_key,
                           const bool intrinsics = true) noexcept;

  bool IsValid() const final override { return valid; }

  std::uint32_t GetKeySize() final override;
  std::uint32_t GetBlockSize() final override;

 private:
  bool valid = false;
  bool intrinsics = false;

  // unit is bit
  std::uint32_t key_size = 0;

  std::array<std::array<std::byte, 4>, 4 * 15> expanded_key;
  std::array<std::array<std::byte, 4>, 4> state;

  static const std::uint8_t S_box[256];
  static const std::uint8_t Inv_S_box[256];

  static std::array<std::byte, 14> Rcon_memo;
  static int Rcon_memo_index;

  constexpr static std::array<std::byte, 4> SubWord(
      const std::span<const std::byte> bytes) noexcept;
  constexpr static std::array<std::byte, 4> RotWord(
      const std::span<const std::byte> bytes) noexcept;
  constexpr static std::byte Rcon(const std::uint32_t i) noexcept;

  constexpr static void AddRoundKey(
      std::array<std::array<std::byte, 4>, 4>& state,
      const std::span<const std::array<std::byte, 4>> round_key) noexcept;
  constexpr static void InvMixColumns(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
  constexpr static void InvShiftRows(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
  constexpr static void InvSubBytes(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
  constexpr static void MixColumns(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
  constexpr static void ShiftRows(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
  constexpr static void SubBytes(
      std::array<std::array<std::byte, 4>, 4>& state) noexcept;
};

}  // namespace bedrock::cipher

#endif
