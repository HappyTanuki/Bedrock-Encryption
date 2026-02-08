#include <emmintrin.h>

#include <cassert>
#include <cstring>

#include "encryption/block_cipher/aes.h"

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

static inline std::uint8_t gf_xtime(std::uint8_t a) noexcept {
  uint8_t x = a;
  uint8_t hi = x & 0x80;
  x <<= 1;
  x ^= (hi ? 0x1B : 0x00);
  return static_cast<std::uint8_t>(x);
}

static inline std::uint8_t gf_mul(std::uint8_t x, std::uint8_t y) noexcept {
  uint8_t r = 0;

  for (int i = 0; i < 8; ++i) {
    r ^= (y & 1) ? x : 0;
    uint8_t hi = x & 0x80;
    x <<= 1;
    x ^= (hi ? 0x1B : 0x00);
    y >>= 1;
  }

  return r;
}

static inline uint8_t gf_pow(uint8_t a, int e) {
  uint8_t r = 1;
  while (e) {
    if (e & 1) r = gf_mul(r, a);
    a = gf_mul(a, a);
    e >>= 1;
  }
  return r;
}

static inline uint8_t gf_inv(uint8_t a) { return a ? gf_pow(a, 254) : 0; }

static inline uint8_t rotl8(uint8_t x, int n) {
  return (x << n) | (x >> (8 - n));
}

constexpr AESMatrix::AESMatrix(
    std::initializer_list<std::initializer_list<std::uint8_t>> init) {
  int i = 0;
  for (auto& row : init) {
    int j = 0;
    for (auto& val : row) {
      value[i][j++] = val;
    }
    i++;
  }
}

constexpr AESMatrix AESMatrix::operator*(const std::uint8_t& scalar) const {
  AESMatrix result;

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = gf_mul(value[i][j], scalar);
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
            result.value[i][j] ^ gf_mul(value[i][k], matrix.value[k][j]);
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

AES_SOFT::~AES_SOFT() = default;

inline void transpose(std::span<const std::uint8_t> word,
                      std::span<std::uint8_t> out) {
  std::array<std::uint8_t, 16> tmp;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      tmp[row * 4 + col] = word[col * 4 + row];
    }
  }

  std::memcpy(out.data(), tmp.data(), 16);
}

void AES_SOFT::EncryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  transpose(block, state);

  AddRoundKey(state, round_keys[0]);

  for (int round = 1; round < Nr; round++) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, round_keys[round]);
  }
  SubBytes(state);
  ShiftRows(state);
  AddRoundKey(state, round_keys[Nr]);

  transpose(state, out);

  return;
}

void AES_SOFT::DecryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  transpose(block, state);

  AddRoundKey(state, round_keys[Nr]);

  // Equivalent Inverse Cipher
  for (int round = Nr - 1; round > 0; round--) {
    InvSubBytes(state);
    InvShiftRows(state);
    InvMixColumns(state);
    AddRoundKey(state, round_keys[round]);
  }
  InvShiftRows(state);
  InvSubBytes(state);
  AddRoundKey(state, round_keys[0]);

  transpose(state, out);

  return;
}

void AES_SOFT::KeyExpantion(
    std::span<const std::uint8_t> key,
    std::span<std::array<std::uint8_t, 16>> enc_round_keys,
    std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  assert(enc_round_keys.size() >= Nr + 1 && dec_round_keys.size() >= Nr + 1);

  std::memcpy(enc_round_keys.data(), key.data(), key.size());

  std::uint32_t temp3;

  for (std::size_t i = Nk; i < 4 * (Nr + 1); i++) {
    temp3 = reinterpret_cast<std::uint32_t*>(enc_round_keys[0].data())[i - 1];

    if (i % Nk == 0) {
      temp3 = SubWord(RotWord(temp3)) ^ Rcon(i / Nk);
    } else if (Nk > 6 && i % Nk == 4) {
      temp3 = SubWord(temp3);
    }

    reinterpret_cast<std::uint32_t*>(enc_round_keys[0].data())[i] =
        temp3 ^
        reinterpret_cast<std::uint32_t*>(enc_round_keys[0].data())[i - Nk];
  }

  std::copy(enc_round_keys.begin(), enc_round_keys.end(),
            dec_round_keys.begin());

  for (int i = 1; i < Nr; ++i) {
    transpose(dec_round_keys[i], dec_round_keys[i]);
    InvMixColumns(dec_round_keys[i]);
    transpose(dec_round_keys[i], dec_round_keys[i]);
  }
  dec_round_keys[0] = enc_round_keys[0];
  dec_round_keys[Nr] = enc_round_keys[Nr];

  return;
}

inline std::uint32_t AES_SOFT::SubWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = S_box(word_ptr[0]);
  result_ptr[1] = S_box(word_ptr[1]);
  result_ptr[2] = S_box(word_ptr[2]);
  result_ptr[3] = S_box(word_ptr[3]);

  return result;
}

inline std::uint32_t AES_SOFT::RotWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = word_ptr[1];
  result_ptr[1] = word_ptr[2];
  result_ptr[2] = word_ptr[3];
  result_ptr[3] = word_ptr[0];

  return result;
}

constexpr std::uint8_t AES_SOFT::Rcon(const std::uint32_t i) noexcept {
  if (Rcon_memo[i] != static_cast<std::uint8_t>(0x00)) return Rcon_memo[i];

  for (int j = Rcon_memo_index + 1; j <= i; j++) {
    Rcon_memo[j] = gf_mul(Rcon_memo[j - 1], static_cast<std::uint8_t>(0x02));
  }

  Rcon_memo_index = i;

  return Rcon_memo[i];
}

constexpr void AES_SOFT::AddRoundKey(
    std::span<std::uint8_t> state,
    std::span<const std::uint8_t> round_key) noexcept {
  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      state[row * 4 + col] = state[row * 4 + col] ^ round_key[col * 4 + row];
    }
  }
}

// inline void AES_SOFT::InvMixColumns(std::span<std::uint8_t> state) noexcept {
//   AESMatrix a = {{0x0e, 0x0b, 0x0d, 0x09},
//                  {0x09, 0x0e, 0x0b, 0x0d},
//                  {0x0d, 0x09, 0x0e, 0x0b},
//                  {0x0b, 0x0d, 0x09, 0x0e}};

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

inline void AES_SOFT::InvMixColumns(std::span<std::uint8_t> state) noexcept {
  for (int c = 0; c < 4; ++c) {
    uint8_t s0 = state[0 * 4 + c];
    uint8_t s1 = state[1 * 4 + c];
    uint8_t s2 = state[2 * 4 + c];
    uint8_t s3 = state[3 * 4 + c];

    // s * 2, 4, 8 계산 (GF(2^8))
    uint8_t s0_2 = gf_xtime(s0);
    uint8_t s1_2 = gf_xtime(s1);
    uint8_t s2_2 = gf_xtime(s2);
    uint8_t s3_2 = gf_xtime(s3);

    uint8_t s0_4 = gf_xtime(s0_2);
    uint8_t s1_4 = gf_xtime(s1_2);
    uint8_t s2_4 = gf_xtime(s2_2);
    uint8_t s3_4 = gf_xtime(s3_2);

    uint8_t s0_8 = gf_xtime(s0_4);
    uint8_t s1_8 = gf_xtime(s1_4);
    uint8_t s2_8 = gf_xtime(s2_4);
    uint8_t s3_8 = gf_xtime(s3_4);

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

    state[0 * 4 + c] = u0;
    state[1 * 4 + c] = u1;
    state[2 * 4 + c] = u2;
    state[3 * 4 + c] = u3;
  }
}

inline void AES_SOFT::InvShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::array<std::uint8_t, 4>, 4> shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][(col + row) % 4] = state[row * 4 + col];
    }
  }

  std::memcpy(state.data(), shifted.data(), 16);
}

constexpr void AES_SOFT::InvSubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = Inv_S_box(state[i]);
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

constexpr void AES_SOFT::MixColumns(std::span<std::uint8_t> state) noexcept {
  // 각 column은 독립적으로 처리됨
  for (int c = 0; c < 4; ++c) {
    uint8_t s0 = state[0 * 4 + c];
    uint8_t s1 = state[1 * 4 + c];
    uint8_t s2 = state[2 * 4 + c];
    uint8_t s3 = state[3 * 4 + c];

    // 공통 XOR (s0 ^ s1 ^ s2 ^ s3)
    uint8_t t = s0 ^ s1 ^ s2 ^ s3;

    // 각 항은 (si ^ s(i+1)) * 2 를 xtime으로 계산
    uint8_t u0 = s0 ^ t ^ gf_xtime(s0 ^ s1);
    uint8_t u1 = s1 ^ t ^ gf_xtime(s1 ^ s2);
    uint8_t u2 = s2 ^ t ^ gf_xtime(s2 ^ s3);
    uint8_t u3 = s3 ^ t ^ gf_xtime(s3 ^ s0);

    state[0 * 4 + c] = u0;
    state[1 * 4 + c] = u1;
    state[2 * 4 + c] = u2;
    state[3 * 4 + c] = u3;
  }
}

inline void AES_SOFT::ShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::uint8_t, 16> shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row * 4 + col] = state[row * 4 + (col + row) % 4];
    }
  }

  std::copy(shifted.begin(), shifted.end(), state.begin());
}

constexpr void AES_SOFT::SubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = S_box(state[i]);
  }
}

std::array<std::uint8_t, 14> AES_SOFT::Rcon_memo = {
    static_cast<std::uint8_t>(0x00), static_cast<std::uint8_t>(0x01),
    static_cast<std::uint8_t>(0x02)};
int AES_SOFT::Rcon_memo_index = 1;

std::uint8_t AES_SOFT::S_box(std::uint8_t x) {
  uint8_t y = gf_inv(x);

  uint8_t s = y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63;

  return s;
}

std::uint8_t AES_SOFT::Inv_S_box(std::uint8_t x) {
  uint8_t y = rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05;

  return gf_inv(y);
}

}  // namespace bedrock::cipher