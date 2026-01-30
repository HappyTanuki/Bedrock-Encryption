#include "encryption/block_cipher/aes.h"

#include <emmintrin.h>

#include <cassert>
#include <cstring>

#include "common/intrinsics.h"

namespace bedrock::cipher {

enum IntrinSet { kAESNI, kSSE2, kSSSE3 };

static bool IntrinEnabled(IntrinSet target) {
  static bedrock::intrinsic::Register reg =
      bedrock::intrinsic::GetCPUFeatures();

  static std::array<bool, 3> enabled = {
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "AESNI"),
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSE2"),
      bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSSE3")};

  switch (target) {
    case kAESNI:
      return enabled[target];
    case kSSE2:
      return enabled[target];
    case kSSSE3:
      return enabled[target];
    default:
      return false;
  }
}

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

static uint8_t gf_pow(uint8_t a, int e) {
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

AES::AES(std::span<const std::uint8_t> key) {
  this->key_size = key.size() * 8;

  KeyExpantion(key, enc_round_keys, dec_round_keys);

  // 이 클래스의 생성자는 의도적으로 키가 제공되지 않으면 정의되지 않도록 되어
  // 있기 때문에 이 생성자는 항상 키를 내부에 저장할 수 있다.
  valid = true;
}

AES::~AES() = default;

BlockCipherErrorStatus AES::Encrypt(std::span<const std::uint8_t> block,
                                    std::span<std::uint8_t> out) {
  if (!IsValid()) {
    return BlockCipherErrorStatus::kFailure;
  }

  std::uint32_t Nr = key_size / 32 + 6;
  std::uint32_t round_keys_size = Nr + 1;
  std::span<std::array<std::uint8_t, 16>> round_keys_view = enc_round_keys;

  Encrypt(round_keys_view.subspan(0, round_keys_size), block, out);

  return BlockCipherErrorStatus::kSuccess;
}
BlockCipherErrorStatus AES::Decrypt(std::span<const std::uint8_t> block,
                                    std::span<std::uint8_t> out) {
  if (!IsValid()) {
    return BlockCipherErrorStatus::kFailure;
  }

  std::uint32_t Nr = key_size / 32 + 6;
  std::uint32_t round_keys_size = Nr + 1;
  std::span<std::array<std::uint8_t, 16>> round_keys_view = dec_round_keys;

  Decrypt(round_keys_view.subspan(0, round_keys_size), block, out);

  return BlockCipherErrorStatus::kSuccess;
}

void AES::Encrypt(std::span<const std::array<std::uint8_t, 16>> round_keys,
                  std::span<const std::uint8_t> block,
                  std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  std::copy(block.begin(), block.end(), state.begin());

  AddRoundKey(state, round_keys[0]);

  if (IntrinEnabled(kAESNI) && IntrinEnabled(kSSE2)) {
    __m128i state_128i =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data()));
    const __m128i* _m128_round_keys =
        reinterpret_cast<const __m128i*>(round_keys.data());

    for (int round = 1; round < Nr; round++) {
      state_128i = _mm_aesenc_si128(state_128i, _m128_round_keys[round]);
    }
    state_128i = _mm_aesenclast_si128(state_128i, _m128_round_keys[Nr]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state.data()), state_128i);
  } else {
    // equivalent fallback
    for (int round = 1; round < Nr; round++) {
      SubBytes(state);
      ShiftRows(state);
      MixColumns(state);
      AddRoundKey(state, round_keys[round]);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, round_keys[Nr]);
  }

  std::copy(state.begin(), state.end(), out.begin());

  return;
}

void AES::Decrypt(std::span<const std::array<std::uint8_t, 16>> round_keys,
                  std::span<const std::uint8_t> block,
                  std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  std::copy(block.begin(), block.end(), state.begin());

  AddRoundKey(state, round_keys[Nr]);

  if (IntrinEnabled(kAESNI) && IntrinEnabled(kSSE2)) {
    __m128i state_128i =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(state.data()));

    for (int round = Nr - 1; round > 0; --round) {
      state_128i = _mm_aesdec_si128(
          state_128i,
          reinterpret_cast<const __m128i*>(round_keys.data())[round]);
    }
    state_128i = _mm_aesdeclast_si128(
        state_128i, reinterpret_cast<const __m128i*>(round_keys.data())[0]);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state.data()), state_128i);
  } else {
    // equivalent fallback
    for (int round = Nr - 1; round > 0; round--) {
      InvShiftRows(state);
      InvSubBytes(state);
      AddRoundKey(state, round_keys[round]);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, round_keys[0]);
  }

  std::copy(state.begin(), state.end(), out.begin());

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
    default:
      return _mm_set_epi32(0x00, 0x00, 0x00, 0x00);
  }
  return _mm_set_epi32(0x00, 0x00, 0x00, 0x00);
}

void AES::KeyExpantion(
    std::span<const std::uint8_t> key,
    std::span<std::array<std::uint8_t, 16>> enc_round_keys,
    std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  assert(enc_round_keys.size() >= Nr + 1 && dec_round_keys.size() >= Nr + 1);

  std::memcpy(enc_round_keys.data(), key.data(), key.size());

  if (IntrinEnabled(kAESNI) && IntrinEnabled(kSSE2) && key_size == 256) {
    __m128i temp1 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_round_keys[0].data()));
    __m128i temp2 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_round_keys[1].data()));
    __m128i mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);

    int i = 2;
    while (i < Nr - 1) {
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

      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i++].data()),
                       temp);

      temp1 = temp2;
      temp2 = temp;

      temp = AESKeygenAssist(temp, 0);
      mask = _mm_set_epi32(0, 0, 0, 0xFFFFFFFF);
      temp = _mm_shuffle_epi32(temp, _MM_SHUFFLE(2, 2, 2, 2));
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

      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i++].data()),
                       temp);

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

    _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i].data()),
                     temp);

    for (int i = 1; i < Nr; ++i) {
      reinterpret_cast<__m128i*>(dec_round_keys.data())[i] = _mm_aesimc_si128(
          reinterpret_cast<__m128i*>(enc_round_keys.data())[i]);
    }
    dec_round_keys[0] = enc_round_keys[0];
    dec_round_keys[Nr] = enc_round_keys[Nr];
    return;
  }

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
    InvMixColumns(dec_round_keys[i]);
  }
  dec_round_keys[0] = enc_round_keys[0];
  dec_round_keys[Nr] = enc_round_keys[Nr];

  return;
}

std::uint32_t AES::GetKeySize() { return key_size; }

std::uint32_t AES::GetBlockSize() { return 128; }

inline std::uint32_t AES::SubWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = S_box(word_ptr[0]);
  result_ptr[1] = S_box(word_ptr[1]);
  result_ptr[2] = S_box(word_ptr[2]);
  result_ptr[3] = S_box(word_ptr[3]);

  return result;
}

inline std::uint32_t AES::RotWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = word_ptr[1];
  result_ptr[1] = word_ptr[2];
  result_ptr[2] = word_ptr[3];
  result_ptr[3] = word_ptr[0];

  return result;
}

constexpr std::uint8_t AES::Rcon(const std::uint32_t i) noexcept {
  if (Rcon_memo[i] != static_cast<std::uint8_t>(0x00)) return Rcon_memo[i];

  for (int j = Rcon_memo_index + 1; j <= i; j++) {
    Rcon_memo[j] = gf_mul(Rcon_memo[j - 1], static_cast<std::uint8_t>(0x02));
  }

  Rcon_memo_index = i;

  return Rcon_memo[i];
}

constexpr void AES::AddRoundKey(
    std::span<std::uint8_t> state,
    std::span<const std::uint8_t> round_key) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = state[i] ^ round_key[i];
  }
}

inline void AES::InvMixColumns(std::span<std::uint8_t> state) noexcept {
  if (IntrinEnabled(kAESNI)) {
    __m128i block =
        _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data()));

    block = _mm_aesimc_si128(block);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(state.data()), block);
    return;
  }

  AESMatrix a = {{0x0e, 0x0b, 0x0d, 0x09},
                 {0x09, 0x0e, 0x0b, 0x0d},
                 {0x0d, 0x09, 0x0e, 0x0b},
                 {0x0b, 0x0d, 0x09, 0x0e}};

  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      column[row][0] = state[row * 4 + col];
    }

    column = a * column;

    for (int row = 0; row < 4; row++) {
      state[row * 4 + col] = column[row][0];
    }
  }
}

inline void AES::InvShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::array<std::uint8_t, 4>, 4> shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][(col + row) % 4] = state[row * 4 + col];
    }
  }

  std::memcpy(state.data(), shifted.data(), 16);
}

constexpr void AES::InvSubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = Inv_S_box(state[i]);
  }
}

constexpr void AES::MixColumns(std::span<std::uint8_t> state) noexcept {
  AESMatrix a = {{0x02, 0x03, 0x01, 0x01},
                 {0x01, 0x02, 0x03, 0x01},
                 {0x01, 0x01, 0x02, 0x03},
                 {0x03, 0x01, 0x01, 0x02}};
  AESMatrix column;
  column.cols = 1;

  for (int col = 0; col < 4; col++) {
    for (int row = 0; row < 4; row++) {
      column[row][0] = state[row * 4 + col];
    }

    column = a * column;

    for (int row = 0; row < 4; row++) {
      state[row * 4 + col] = column[row][0];
    }
  }
}

inline void AES::ShiftRows(std::span<std::uint8_t> state) noexcept {
  std::array<std::array<std::uint8_t, 4>, 4> shifted;

  for (int row = 0; row < 4; row++) {
    for (int col = 0; col < 4; col++) {
      shifted[row][col] = state[row * 4 + (col + row) % 4];
    }
  }

  std::memcpy(state.data(), shifted.data(), 16);
}

constexpr void AES::SubBytes(std::span<std::uint8_t> state) noexcept {
  for (int i = 0; i < 16; i++) {
    state[i] = S_box(state[i]);
  }
}

std::array<std::uint8_t, 14> AES::Rcon_memo = {static_cast<std::uint8_t>(0x00),
                                               static_cast<std::uint8_t>(0x01),
                                               static_cast<std::uint8_t>(0x02)};
int AES::Rcon_memo_index = 1;

std::uint8_t AES::S_box(std::uint8_t x) {
  uint8_t y = gf_inv(x);

  uint8_t s = y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63;

  return s;
}

std::uint8_t AES::Inv_S_box(std::uint8_t x) {
  uint8_t y = rotl8(x, 1) ^ rotl8(x, 3) ^ rotl8(x, 6) ^ 0x05;

  return gf_inv(y);
}

}  // namespace bedrock::cipher