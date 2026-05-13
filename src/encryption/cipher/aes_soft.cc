#include <emmintrin.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <utility>

#include "encryption/cipher/aes.h"

namespace bedrock::cipher {

struct AESMatrix {
 public:
  constexpr AESMatrix() = default;
  constexpr explicit AESMatrix(std::array<std::array<std::uint8_t, 4>, 4> value)
      : value(value) {}
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

static inline std::uint8_t GfXtime(std::uint8_t a) noexcept {
  uint8_t x = a;
  uint8_t hi = x & 0x80;
  x <<= 1;
  x ^= ((hi != 0U) ? 0x1B : 0x00);
  return static_cast<std::uint8_t>(x);
}

static inline std::uint8_t GfMul(std::uint8_t x, std::uint8_t y) noexcept {
  uint8_t r = 0;

  for (int i = 0; i < 8; ++i) {
    r ^= ((y & 1) != 0) ? x : 0;
    uint8_t hi = x & 0x80;
    x <<= 1;
    x ^= ((hi != 0U) ? 0x1B : 0x00);
    y >>= 1;
  }

  return r;
}

static inline uint8_t GfPow(uint8_t a, int e) {
  uint8_t r = 1;
  while (e != 0) {
    if ((e & 1) != 0) {
      r = GfMul(r, a);
    }
    a = GfMul(a, a);
    e >>= 1;
  }
  return r;
}

static inline uint8_t GfInv(uint8_t a) { return (a != 0U) ? GfPow(a, 254) : 0; }

static inline uint8_t Rotl8(uint8_t x, int n) {
  return (x << n) | (x >> (8 - n));
}

constexpr AESMatrix::AESMatrix(
    std::initializer_list<std::initializer_list<std::uint8_t>> init) {
  int i = 0;
  for (const auto& row : init) {
    int j = 0;
    for (const auto& val : row) {
      value[i][j++] = val;
    }
    i++;
  }
}

constexpr AESMatrix AESMatrix::operator*(const std::uint8_t& scalar) const {
  AESMatrix result;

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = GfMul(value[i][j], scalar);
    }
  }

  return result;
}
constexpr AESMatrix operator*(std::uint8_t lhs, const AESMatrix& matrix) {
  return matrix * lhs;
}

constexpr AESMatrix AESMatrix::operator*(const AESMatrix& matrix) const {
  AESMatrix result;

  if (cols != matrix.rows) {
    return result;
  }

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < matrix.cols; j++) {
      for (int k = 0; k < cols; k++) {
        result.value[i][j] =
            result.value[i][j] ^ GfMul(value[i][k], matrix.value[k][j]);
      }
    }
  }

  result.rows = rows;
  result.cols = matrix.cols;

  return result;
}

constexpr AESMatrix AESMatrix::operator+(const AESMatrix& matrix) const {
  AESMatrix result;

  if (rows != matrix.rows || cols != matrix.cols) {
    return result;
  }

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = value[i][j] ^ matrix.value[i][j];
    }
  }

  return result;
}

AesSoft::~AesSoft() = default;

inline void Transpose(std::span<const std::uint8_t> word,
                      std::span<std::uint8_t> out) {
  std::array<std::uint8_t, 16> tmp{};

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      tmp[(row * 4) + col] = word[(col * 4) + row];
    }
  }

  std::memcpy(out.data(), tmp.data(), 16);
}

void AesSoft::EncryptImpl(BlockCipherCTX& ctx,
                          std::span<const std::uint8_t> block,
                          std::span<std::uint8_t> out) const noexcept {
  Transpose(block, ctx.state);

  AddRoundKey(ctx.state, ctx.enc_round_keys[0]);

  for (int round = 1; std::cmp_less(round, ctx.nr); round++) {
    SubBytes(ctx.state);
    ShiftRows(ctx.state);
    MixColumns(ctx.state);
    AddRoundKey(ctx.state, ctx.enc_round_keys[round]);
  }
  SubBytes(ctx.state);
  ShiftRows(ctx.state);
  AddRoundKey(ctx.state, ctx.enc_round_keys[ctx.nr]);

  Transpose(ctx.state, out);
}

void AesSoft::DecryptImpl(BlockCipherCTX& ctx,
                          std::span<const std::uint8_t> block,
                          std::span<std::uint8_t> out) const noexcept {
  Transpose(block, ctx.state);

  AddRoundKey(ctx.state, ctx.dec_round_keys[ctx.nr]);

  // Equivalent Inverse Cipher
  for (int round = ctx.nr - 1; round > 0; round--) {
    InvSubBytes(ctx.state);
    InvShiftRows(ctx.state);
    InvMixColumns(ctx.state);
    AddRoundKey(ctx.state, ctx.dec_round_keys[round]);
  }
  InvShiftRows(ctx.state);
  InvSubBytes(ctx.state);
  AddRoundKey(ctx.state, ctx.dec_round_keys[0]);

  Transpose(ctx.state, out);
}

ErrorStatus AesSoft::KeyExpantion(std::span<const std::uint8_t> key,
                                  BlockCipherCTX& ctx) const noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t nk = key_size / 32;
  std::uint32_t nr = nk + 6;

  if (ctx.enc_round_keys.size() < nr + 1 ||
      ctx.dec_round_keys.size() < nr + 1) {
    return ErrorStatus::kFailure;
  }

  std::memcpy(ctx.enc_round_keys.data(), key.data(), key.size());

  std::uint32_t temp3 = 0;

  for (std::size_t i = nk; i < static_cast<std::size_t>(4 * (nr + 1)); i++) {
    temp3 =
        reinterpret_cast<std::uint32_t*>(ctx.enc_round_keys[0].data())[i - 1];

    if (i % nk == 0) {
      temp3 = SubWord(RotWord(temp3)) ^ kRcon[i / nk];
    } else if (nk > 6 && i % nk == 4) {
      temp3 = SubWord(temp3);
    }

    reinterpret_cast<std::uint32_t*>(ctx.enc_round_keys[0].data())[i] =
        temp3 ^
        reinterpret_cast<std::uint32_t*>(ctx.enc_round_keys[0].data())[i - nk];
  }

  std::ranges::copy(ctx.enc_round_keys, ctx.dec_round_keys.begin());

  for (int i = 1; std::cmp_less(i, nr); ++i) {
    Transpose(ctx.dec_round_keys[i], ctx.dec_round_keys[i]);
    InvMixColumns(ctx.dec_round_keys[i]);
    Transpose(ctx.dec_round_keys[i], ctx.dec_round_keys[i]);
  }
  ctx.dec_round_keys[0] = ctx.enc_round_keys[0];
  ctx.dec_round_keys[nr] = ctx.enc_round_keys[nr];

  return ErrorStatus::kSuccess;
}

inline std::uint32_t AesSoft::SubWord(const std::uint32_t word) noexcept {
  std::uint32_t result = 0;
  const auto* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  auto* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = SBox(word_ptr[0]);
  result_ptr[1] = SBox(word_ptr[1]);
  result_ptr[2] = SBox(word_ptr[2]);
  result_ptr[3] = SBox(word_ptr[3]);

  return result;
}

inline std::uint32_t AesSoft::RotWord(const std::uint32_t word) noexcept {
  std::uint32_t result = 0;
  const auto* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  auto* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = word_ptr[1];
  result_ptr[1] = word_ptr[2];
  result_ptr[2] = word_ptr[3];
  result_ptr[3] = word_ptr[0];

  return result;
}

//constexpr std::uint8_t AES_SOFT::Rcon(const std::uint32_t i) noexcept {
//  if (kRcon[i] != static_cast<std::uint8_t>(0x00)) return kRcon[i];
//
//  for (int j = Rcon_memo_index + 1; j <= i; j++) {
//    Rcon_memo[j] = gf_mul(Rcon_memo[j - 1], static_cast<std::uint8_t>(0x02));
//  }
//
//  Rcon_memo_index = i;
//
//  return Rcon_memo[i];
//}

constexpr void AesSoft::AddRoundKey(
    std::span<std::uint8_t> state,
    std::span<const std::uint8_t> round_key) noexcept {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      state[(row * 4) + col] =
          state[(row * 4) + col] ^ round_key[(col * 4) + row];
    }
  }
}

inline void AesSoft::InvMixColumns(std::span<std::uint8_t> state) noexcept {
  for (int c = 0; c < 4; ++c) {
    uint8_t s0 = state[(0 * 4) + c];
    uint8_t s1 = state[(1 * 4) + c];
    uint8_t s2 = state[(2 * 4) + c];
    uint8_t s3 = state[(3 * 4) + c];

    // s * 2, 4, 8 계산 (GF(2^8))
    uint8_t s0_2 = GfXtime(s0);
    uint8_t s1_2 = GfXtime(s1);
    uint8_t s2_2 = GfXtime(s2);
    uint8_t s3_2 = GfXtime(s3);

    uint8_t s0_4 = GfXtime(s0_2);
    uint8_t s1_4 = GfXtime(s1_2);
    uint8_t s2_4 = GfXtime(s2_2);
    uint8_t s3_4 = GfXtime(s3_2);

    uint8_t s0_8 = GfXtime(s0_4);
    uint8_t s1_8 = GfXtime(s1_4);
    uint8_t s2_8 = GfXtime(s2_4);
    uint8_t s3_8 = GfXtime(s3_4);

    // 0e = 8 ^ 4 ^ 2
    // 0b = 8 ^ 2 ^ 1
    // 0d = 8 ^ 4 ^ 1
    // 09 = 8 ^ 1
    uint8_t u0 = (s0_8 ^ s0_4 ^ s0_2) ^ (s1_8 ^ s1_2 ^ s1) ^
                 (s2_8 ^ s2_4 ^ s2) ^ (s3_8 ^ s3);

    uint8_t u1 = (s0_8 ^ s0) ^ (s1_8 ^ s1_4 ^ s1_2) ^ (s2_8 ^ s2_2 ^ s2) ^
                 (s3_8 ^ s3_4 ^ s3);

    uint8_t u2 = (s0_8 ^ s0_4 ^ s0) ^ (s1_8 ^ s1) ^ (s2_8 ^ s2_4 ^ s2_2) ^
                 (s3_8 ^ s3_2 ^ s3);

    uint8_t u3 = (s0_8 ^ s0_2 ^ s0) ^ (s1_8 ^ s1_4 ^ s1) ^ (s2_8 ^ s2) ^
                 (s3_8 ^ s3_4 ^ s3_2);

    state[(0 * 4) + c] = u0;
    state[(1 * 4) + c] = u1;
    state[(2 * 4) + c] = u2;
    state[(3 * 4) + c] = u3;
  }
}

inline void AesSoft::InvShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::array<std::uint8_t, 4>, 4> shifted{};

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][(col + row) % 4] = state[(row * 4) + col];
    }
  }

  std::memcpy(state.data(), shifted.data(), 16);
}

constexpr void AesSoft::InvSubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = InvSBox(state[i]);
  }
}

// constexpr void AES_SOFT::MixColumns(std::span<std::uint8_t> state) noexcept {
//   AESMatrix a = {{0x02, 0x03, 0x01, 0x01},
//                  {0x01, 0x02, 0x03, 0x01},
//                  {0x01, 0x01, 0x02, 0x03},
//                  {0x03, 0x01, 0x01, 0x02}};
//   AESMatrix column;
//   column.cols = 1;

//   for (int col = 0; col < 4; col++) {
//     for (int row = 0; row < 4; row++) {
//       column[row][0] = state[row * 4 + col];
//     }

//     column = a * column;

//     for (int row = 0; row < 4; row++) {
//       state[row * 4 + col] = column[row][0];
//     }
//   }
// }

constexpr void AesSoft::MixColumns(std::span<std::uint8_t> state) noexcept {
  // 각 column은 독립적으로 처리됨
  for (int c = 0; c < 4; ++c) {
    uint8_t s0 = state[(0 * 4) + c];
    uint8_t s1 = state[(1 * 4) + c];
    uint8_t s2 = state[(2 * 4) + c];
    uint8_t s3 = state[(3 * 4) + c];

    // 공통 XOR (s0 ^ s1 ^ s2 ^ s3)
    uint8_t t = s0 ^ s1 ^ s2 ^ s3;

    // 각 항은 (si ^ s(i+1)) * 2 를 xtime으로 계산
    uint8_t u0 = s0 ^ t ^ GfXtime(s0 ^ s1);
    uint8_t u1 = s1 ^ t ^ GfXtime(s1 ^ s2);
    uint8_t u2 = s2 ^ t ^ GfXtime(s2 ^ s3);
    uint8_t u3 = s3 ^ t ^ GfXtime(s3 ^ s0);

    state[(0 * 4) + c] = u0;
    state[(1 * 4) + c] = u1;
    state[(2 * 4) + c] = u2;
    state[(3 * 4) + c] = u3;
  }
}

inline void AesSoft::ShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::uint8_t, 16> shifted{};

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[(row * 4) + col] = state[(row * 4) + ((col + row) % 4)];
    }
  }

  std::ranges::copy(shifted, state.begin());
}

constexpr void AesSoft::SubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = SBox(state[i]);
  }
}

//std::array<std::uint8_t, 14> AES_SOFT::Rcon_memo = {
//    static_cast<std::uint8_t>(0x00), static_cast<std::uint8_t>(0x01),
//    static_cast<std::uint8_t>(0x02)};
//int AES_SOFT::Rcon_memo_index = 1;

std::uint8_t AesSoft::SBox(std::uint8_t x) {
  uint8_t y = GfInv(x);

  uint8_t s = y ^ Rotl8(y, 1) ^ Rotl8(y, 2) ^ Rotl8(y, 3) ^ Rotl8(y, 4) ^ 0x63;

  return s;
}

std::uint8_t AesSoft::InvSBox(std::uint8_t x) {
  uint8_t y = Rotl8(x, 1) ^ Rotl8(x, 3) ^ Rotl8(x, 6) ^ 0x05;

  return GfInv(y);
}

}  // namespace bedrock::cipher