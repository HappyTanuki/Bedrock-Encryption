#include "encryption/block_cipher/aes.h"

#include <cassert>
#include <cstddef>
#include <cstring>

#include "common/intrinsics.h"
#include "immintrin.h"

namespace bedrock::cipher {

static constexpr std::array<std::array<std::byte, 256>, 256> generate_LUT() {
  std::array<std::array<std::byte, 256>, 256> table = {};

  for (int a = 0; a < 256; ++a) {
    for (int b = 0; b < 256; ++b) {
      std::uint8_t aa = a;
      std::uint8_t bb = b;
      std::uint8_t p = 0;
      for (int i = 0; i < 8; ++i) {
        if (bb & 1) p ^= aa;
        bool hi_bit = (aa & 0x80);
        aa <<= 1;
        if (hi_bit) aa ^= 0x1B;  // AES irreducible polynomial
        bb >>= 1;
      }
      table[a][b] = static_cast<std::byte>(p);
    }
  }
  return table;
}

inline static const std::array<std::array<std::byte, 256>, 256> mul_table =
    generate_LUT();

constexpr AESMatrix::AESMatrix(
    std::initializer_list<std::initializer_list<std::byte>> init) {
  int i = 0;
  for (auto& row : init) {
    int j = 0;
    for (auto& val : row) {
      value[i][j++] = val;
    }
    i++;
  }
}

constexpr AESMatrix::AESMatrix(
    std::initializer_list<std::initializer_list<std::uint8_t>> init) {
  int i = 0;
  for (auto& row : init) {
    int j = 0;
    for (auto& val : row) {
      value[i][j++] = static_cast<std::byte>(val);
    }
    i++;
  }
}

constexpr AESMatrix AESMatrix::operator*(const std::byte& scalar) const {
  AESMatrix result;

  for (int i = 0; i < rows; i++) {
    for (int j = 0; j < cols; j++) {
      result.value[i][j] = mul_table[std::to_integer<std::uint8_t>(value[i][j])]
                                    [std::to_integer<std::uint8_t>(scalar)];
    }
  }

  return result;
}
constexpr AESMatrix operator*(std::byte lhs, const AESMatrix& matrix) {
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
            result.value[i][j] ^
            mul_table[std::to_integer<std::uint8_t>(value[i][k])]
                     [std::to_integer<std::uint8_t>(matrix.value[k][j])];
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

AES::AES(const std::span<const std::byte> key) {
  bedrock::intrinsic::Register reg = bedrock::intrinsic::GetCPUFeatures();

  intrinsics = bedrock::intrinsic::IsCpuEnabledFeature(reg, "AESNI") &&
               bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSE2");

  this->key_size = key.size() * 8;

  KeyExpantion(key, expanded_key);

  // AES의 생성자는 의도적으로 키가 제공되지 않으면 정의되지 않도록 되어 있기
  // 때문에 이 생성자는 항상 키를 내부에 저장할 수 있다.
  valid = true;
}

AES::~AES() = default;

BlockCipherErrorStatus AES::Encrypt(const std::span<const std::byte> block,
                                    std::span<std::byte> out) {
  if (!IsValid()) {
    return BlockCipherErrorStatus::kFailure;
  }

  std::uint32_t Nr = key_size / 32 + 6;
  std::uint32_t expanded_key_size = 4 * (Nr + 1);
  const std::span<const std::array<std::byte, 4>> expanded_key_view =
      expanded_key;

  Encrypt(expanded_key_view.subspan(0, expanded_key_size), block, out,
          intrinsics);

  return BlockCipherErrorStatus::kSuccess;
}
BlockCipherErrorStatus AES::Decrypt(const std::span<const std::byte> block,
                                    std::span<std::byte> out) {
  if (!IsValid()) {
    return BlockCipherErrorStatus::kFailure;
  }

  std::uint32_t Nr = key_size / 32 + 6;
  std::uint32_t expanded_key_size = 4 * (Nr + 1);
  const std::span<const std::array<std::byte, 4>> expanded_key_view =
      expanded_key;

  Decrypt(expanded_key_view.subspan(0, expanded_key_size), block, out,
          intrinsics);

  return BlockCipherErrorStatus::kSuccess;
}

void AES::Encrypt(const std::span<const std::array<std::byte, 4>> expanded_key,
                  const std::span<const std::byte> block,
                  std::span<std::byte> out, const bool intrinsics) noexcept {
  auto block_iter = block.begin();
  const std::span<const std::array<std::byte, 4>> expanded_key_view =
      expanded_key;
  std::array<std::array<std::byte, 4>, 4> state;
  std::uint32_t Nr = expanded_key.size() / 4 - 1;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      state[i][j] = *block_iter++;
    }
  }

  AddRoundKey(state, expanded_key_view.subspan(0, 4));

  if (intrinsics) {
    std::byte buffer[16];
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        buffer[i * 4 + j] = state[j][i];
      }
    }

    __m128i state_128i =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));
    std::vector<__m128i> round_keys(Nr + 1);

    for (int j = 0; j < Nr + 1; j++) {
      for (int i = 0; i < 4; ++i) {
        std::memcpy(buffer + i * 4, expanded_key[j * 4 + i].data(), 4);
      }
      round_keys[j] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));
    }

    for (int round = 1; round < Nr; round++) {
      state_128i = _mm_aesenc_si128(state_128i, round_keys[round]);
    }
    state_128i = _mm_aesenclast_si128(state_128i, round_keys[Nr]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(buffer), state_128i);
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[j][i] = buffer[i * 4 + j];
      }
    }
  } else {
    // equivalent fallback
    for (int round = 1; round < Nr; round++) {
      SubBytes(state);
      ShiftRows(state);
      MixColumns(state);
      AddRoundKey(state, expanded_key_view.subspan(round * 4, 4));
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, expanded_key_view.subspan(Nr * 4, 4));
  }

  auto out_iter = out.begin();

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      *out_iter++ = state[i][j];
    }
  }

  return;
}

void AES::Decrypt(const std::span<const std::array<std::byte, 4>> expanded_key,
                  const std::span<const std::byte> block,
                  std::span<std::byte> out, const bool intrinsics) noexcept {
  auto block_iter = block.begin();
  const std::span<const std::array<std::byte, 4>> expanded_key_view =
      expanded_key;
  std::array<std::array<std::byte, 4>, 4> state;
  std::uint32_t Nr = expanded_key.size() / 4 - 1;

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      state[i][j] = *block_iter++;
    }
  }

  AddRoundKey(state, expanded_key_view.subspan(Nr * 4, 4));

  if (intrinsics) {
    std::byte buffer[16];
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        buffer[i * 4 + j] = state[j][i];
      }
    }

    __m128i state_128i =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));
    std::vector<__m128i> round_keys(Nr + 1);

    for (int r = 1; r < Nr; ++r) {
      for (int w = 0; w < 4; ++w) {
        std::memcpy(buffer + w * 4, expanded_key[r * 4 + w].data(), 4);
      }
      round_keys[r] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));
      round_keys[r] = _mm_aesimc_si128(round_keys[r]);
    }
    for (int w = 0; w < 4; ++w) {
      std::memcpy(buffer + w * 4, expanded_key[w].data(), 4);
    }

    round_keys[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(buffer));

    for (int round = Nr - 1; round > 0; --round) {
      state_128i = _mm_aesdec_si128(state_128i, round_keys[round]);
    }
    state_128i = _mm_aesdeclast_si128(state_128i, round_keys[0]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(buffer), state_128i);
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[j][i] = buffer[i * 4 + j];
      }
    }
  } else {
    // equivalent fallback
    for (int round = Nr - 1; round > 0; round--) {
      InvShiftRows(state);
      InvSubBytes(state);
      AddRoundKey(state, expanded_key_view.subspan(4 * round, 4));
      InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, expanded_key_view.subspan(0, 4));
  }

  auto out_iter = out.begin();

  for (int j = 0; j < 4; j++) {
    for (int i = 0; i < 4; i++) {
      *out_iter++ = state[i][j];
    }
  }

  return;
}

static inline __m128i AESKeygenAssist(__m128i a, int imm) {
  // because api needs const numbers, not variables
  switch (imm) {
    case 0:
      return _mm_aeskeygenassist_si128(a, 0x00);
    case 1:
      return _mm_aeskeygenassist_si128(a, 0x01);
    case 2:
      return _mm_aeskeygenassist_si128(a, 0x02);
    case 3:
      return _mm_aeskeygenassist_si128(a, 0x04);
    case 4:
      return _mm_aeskeygenassist_si128(a, 0x08);
    case 5:
      return _mm_aeskeygenassist_si128(a, 0x10);
    case 6:
      return _mm_aeskeygenassist_si128(a, 0x20);
    case 7:
      return _mm_aeskeygenassist_si128(a, 0x40);
    case 8:
      return _mm_aeskeygenassist_si128(a, 0x80);
    case 9:
      return _mm_aeskeygenassist_si128(a, 0x1b);
    case 10:
      return _mm_aeskeygenassist_si128(a, 0x36);
    case 11:
      return _mm_aeskeygenassist_si128(a, 0x6c);
    case 12:
      return _mm_aeskeygenassist_si128(a, 0xd8);
    case 13:
      return _mm_aeskeygenassist_si128(a, 0xab);
    default:
      return _mm_set_epi32(0x00, 0x00, 0x00, 0x00);
  }
  return _mm_set_epi32(0x00, 0x00, 0x00, 0x00);
}

void AES::KeyExpantion(const std::span<const std::byte> key,
                       std::span<std::array<std::byte, 4>> expanded_key,
                       const bool intrinsics) noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  assert(expanded_key.size() >= 4 * (Nr + 1));

  if (intrinsics && key_size != 192) {
    std::vector<__m128i> round_keys(Nr + 1);
    if (key_size == 256) {
      round_keys[0] =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data()));
      round_keys[1] =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(key.data() + 16));

      __m128i temp1 = round_keys[0];
      __m128i temp2 = round_keys[1];
      __m128i mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);

      int i = 2;
      while (i < Nr - 1) {
        __m128i temp = AESKeygenAssist(temp2, i / 2);
        mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);
        temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3));
        temp = _mm_and_si128(temp, mask);

        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 첫번째 워드 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 두번째 워드까지 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 세번째 워드까지 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 마지막 워드까지 완성

        round_keys[i++] = temp;

        temp1 = temp2;
        temp2 = temp;

        temp = AESKeygenAssist(temp, 0);
        mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);
        temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(2, 2, 2, 2));
        temp = _mm_and_si128(temp, mask);

        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 첫번째 워드 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 두번째 워드까지 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 세번째 워드까지 완성

        temp = _mm_xor_si128(temp,
                             _mm_slli_si128(_mm_and_si128(temp, mask),
                                            4));  // 이전 워드 다음 워드에 복사
        mask = _mm_slli_si128(mask, 4);
        temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                             temp);  // 마지막 워드까지 완성

        round_keys[i++] = temp;

        temp1 = temp2;
        temp2 = temp;
      }

      __m128i temp = AESKeygenAssist(temp2, i / 2);
      mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);
      temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(3, 3, 3, 3));
      temp = _mm_and_si128(temp, mask);

      temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                           temp);  // 첫번째 워드 완성

      temp =
          _mm_xor_si128(temp, _mm_slli_si128(_mm_and_si128(temp, mask),
                                             4));  // 이전 워드 다음 워드에 복사
      mask = _mm_slli_si128(mask, 4);
      temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                           temp);  // 두번째 워드까지 완성

      temp =
          _mm_xor_si128(temp, _mm_slli_si128(_mm_and_si128(temp, mask),
                                             4));  // 이전 워드 다음 워드에 복사
      mask = _mm_slli_si128(mask, 4);
      temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                           temp);  // 세번째 워드까지 완성

      temp =
          _mm_xor_si128(temp, _mm_slli_si128(_mm_and_si128(temp, mask),
                                             4));  // 이전 워드 다음 워드에 복사
      mask = _mm_slli_si128(mask, 4);
      temp = _mm_xor_si128(_mm_and_si128(temp1, mask),
                           temp);  // 마지막 워드까지 완성

      round_keys[i] = temp;

      for (int j = 0; j < Nr + 1; j++) {
        std::uint32_t temp[4];
        _mm_storeu_si128(reinterpret_cast<__m128i*>(temp), round_keys[j]);

        for (int k = 0; k < 4; ++k) {
          std::memcpy(expanded_key[j * 4 + k].data(), &temp[k], 4);
        }
      }
      return;
    }
  }

  std::array<std::byte, 4> temp;

  int i = 0;
  for (i = 0; i < Nk; i++) {
    std::memcpy(expanded_key[i].data(), key.data() + (i * 4), 4);
  }

  while (i < 4 * (Nr + 1)) {
    std::memcpy(temp.data(), expanded_key.data() + (i - 1), 4);

    if (i % Nk == 0) {
      temp = SubWord(RotWord(temp));
      __m128i temp2 = _mm_cvtsi32_si128(
          *reinterpret_cast<const std::uint32_t*>(temp.data()));
      __m128i temp3 =
          _mm_cvtsi32_si128(std::to_integer<std::uint32_t>(Rcon(i / Nk)));
      _mm_storeu_si32(reinterpret_cast<std::uint32_t*>(temp.data()),
                      _mm_xor_si128(temp2, temp3));
    } else if (Nk > 6 && i % Nk == 4) {
      temp = SubWord(temp);
    }

    __m128i temp2 =
        _mm_cvtsi32_si128(*reinterpret_cast<const std::uint32_t*>(temp.data()));
    __m128i temp3 = _mm_cvtsi32_si128(
        *reinterpret_cast<const std::uint32_t*>(expanded_key[i - Nk].data()));
    _mm_storeu_si32(reinterpret_cast<std::uint32_t*>(expanded_key[i].data()),
                    _mm_xor_si128(temp2, temp3));

    i++;
  }

  return;
}

std::uint32_t AES::GetKeySize() { return key_size; }

std::uint32_t AES::GetBlockSize() { return 128; }

// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
constexpr std::array<std::byte, 4> AES::SubWord(
    const std::span<const std::byte> bytes) noexcept {
  std::array<std::byte, 4> result;

  result[0] =
      static_cast<std::byte>(S_box[std::to_integer<std::uint8_t>(bytes[0])]);
  result[1] =
      static_cast<std::byte>(S_box[std::to_integer<std::uint8_t>(bytes[1])]);
  result[2] =
      static_cast<std::byte>(S_box[std::to_integer<std::uint8_t>(bytes[2])]);
  result[3] =
      static_cast<std::byte>(S_box[std::to_integer<std::uint8_t>(bytes[3])]);

  return result;
}

constexpr std::array<std::byte, 4> AES::RotWord(
    const std::span<const std::byte> bytes) noexcept {
  std::array<std::byte, 4> result;

  result[0] = bytes[1];
  result[1] = bytes[2];
  result[2] = bytes[3];
  result[3] = bytes[0];

  return result;
}

constexpr std::byte AES::Rcon(const std::uint32_t i) noexcept {
  if (Rcon_memo[i] != static_cast<std::byte>(0x00)) return Rcon_memo[i];

  for (int j = Rcon_memo_index + 1; j <= i; j++) {
    Rcon_memo[j] = static_cast<std::byte>(
        mul_table[std::to_integer<std::uint32_t>(Rcon_memo[j - 1])][0x02]);
  }

  Rcon_memo_index = i;

  return Rcon_memo[i];
}

constexpr void AES::AddRoundKey(
    std::array<std::array<std::byte, 4>, 4>& state,
    const std::span<const std::array<std::byte, 4>> round_key) noexcept {
  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      state[row][col] = state[row][col] ^ round_key[col][row];
    }
  }
}

constexpr void AES::InvMixColumns(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  AESMatrix a = {{0x0e, 0x0b, 0x0d, 0x09},
                 {0x09, 0x0e, 0x0b, 0x0d},
                 {0x0d, 0x09, 0x0e, 0x0b},
                 {0x0b, 0x0d, 0x09, 0x0e}};
  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      column[row][0] = state[row][col];
    }

    column = a * column;

    for (int row = 0; row < 4; row++) {
      state[row][col] = column[row][0];
    }
  }
}

constexpr void AES::InvShiftRows(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  AESMatrix shifted;

  for (int row = 0; row < 4; row++)
    for (int col = 0; col < 4; col++)
      shifted[row][(col + row) % 4] = state[row][col];

  state = shifted.value;
}

// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
constexpr void AES::InvSubBytes(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[i][j] = static_cast<std::byte>(
          Inv_S_box[std::to_integer<std::uint8_t>(state[i][j])]);
    }
  }
}

constexpr void AES::MixColumns(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  AESMatrix a = {{0x02, 0x03, 0x01, 0x01},
                 {0x01, 0x02, 0x03, 0x01},
                 {0x01, 0x01, 0x02, 0x03},
                 {0x03, 0x01, 0x01, 0x02}};
  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) column[row][0] = state[row][col];

    column = a * column;

    for (int row = 0; row < 4; row++) state[row][col] = column[row][0];
  }
}

constexpr void AES::ShiftRows(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  AESMatrix shifted;

  for (int row = 0; row < 4; row++)
    for (int col = 0; col < 4; col++)
      shifted[row][col] = state[row][(col + row) % 4];

  state = shifted.value;
}

// 캐시 타이밍 공격에 취약함
// 하지만 해결 방법을 이해할 수 없기에 적용하지 않았음
constexpr void AES::SubBytes(
    std::array<std::array<std::byte, 4>, 4>& state) noexcept {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      state[i][j] = static_cast<std::byte>(
          S_box[std::to_integer<std::uint8_t>(state[i][j])]);
    }
  }
}

std::array<std::byte, 14> AES::Rcon_memo = {static_cast<std::byte>(0x00),
                                            static_cast<std::byte>(0x01),
                                            static_cast<std::byte>(0x02)};
int AES::Rcon_memo_index = 1;

const std::uint8_t AES::S_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

const std::uint8_t AES::Inv_S_box[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

}  // namespace bedrock::cipher