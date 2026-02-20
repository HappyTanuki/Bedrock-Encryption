#include <emmintrin.h>
#include <immintrin.h>

#include <cassert>
#include <cstring>
#include <iostream>

#include "encryption/block_cipher/aes.h"
#include "encryption/util/helper.h"

namespace bedrock::cipher {

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

AES_NI::~AES_NI() = default;

void AES_NI::EncryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  std::copy(block.begin(), block.end(), state.begin());

  bedrock::util::XorInplace(state, round_keys[0]);

  __m128i state_128i =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(state.data()));
  const __m128i* _m128_round_keys =
      reinterpret_cast<const __m128i*>(round_keys.data());

  for (int round = 1; round < Nr; round++) {
    state_128i = _mm_aesenc_si128(state_128i, _m128_round_keys[round]);
  }
  state_128i = _mm_aesenclast_si128(state_128i, _m128_round_keys[Nr]);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(state.data()), state_128i);

  std::copy(state.begin(), state.end(), out.begin());

  return;
}

void AES_NI::DecryptImpl(
    std::span<const std::array<std::uint8_t, 16>> round_keys,
    std::span<const std::uint8_t> block, std::span<std::uint8_t> out) noexcept {
  std::array<std::uint8_t, 16> state;
  std::uint32_t Nr = round_keys.size() - 1;

  std::copy(block.begin(), block.end(), state.begin());

  bedrock::util::XorInplace(state, round_keys[Nr]);

  __m128i state_128i =
      _mm_loadu_si128(reinterpret_cast<__m128i*>(state.data()));

  for (int round = Nr - 1; round > 0; --round) {
    state_128i = _mm_aesdec_si128(
        state_128i, reinterpret_cast<const __m128i*>(round_keys.data())[round]);
  }
  state_128i = _mm_aesdeclast_si128(
      state_128i, reinterpret_cast<const __m128i*>(round_keys.data())[0]);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(state.data()), state_128i);

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

void AES_NI::KeyExpantion(
    std::span<const std::uint8_t> key,
    std::span<std::array<std::uint8_t, 16>> enc_round_keys,
    std::span<std::array<std::uint8_t, 16>> dec_round_keys) noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  assert(enc_round_keys.size() >= Nr + 1 && dec_round_keys.size() >= Nr + 1);

  std::memcpy(enc_round_keys.data(), key.data(), key.size());

  if (key_size == 256) {
    __m128i temp1 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_round_keys[0].data()));
    __m128i temp2 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_round_keys[1].data()));

    int i = 2;
    __m128i assist_val = _mm_set_epi32(0, 0, 0, 0);
    while (i < Nr - 1) {
      assist_val = AESKeygenAssist(temp2, i / 2);
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));

      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, assist_val);

      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i++].data()),
                       temp1);

      assist_val = AESKeygenAssist(temp1, 0);
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(2, 2, 2, 2));

      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, assist_val);

      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i++].data()),
                       temp2);
    }

    assist_val = AESKeygenAssist(temp2, i / 2);
    assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));

    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, assist_val);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i++].data()),
                     temp1);

  } else if (key_size == 128) {
    // Round 0 (Original Key)
    __m128i temp1 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_round_keys.data()));

    for (int i = 1; i < Nr + 1; ++i) {
      // 1. Assist 연산 수행 (Rcon 적용)
      __m128i assist_val = AESKeygenAssist(temp1, i);

      // 2. 위에서 정의한 로직으로 다음 라운드 키 계산
      // (간소화를 위해 내부 로직 전개)
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, assist_val);

      // 3. 결과 저장
      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_round_keys[i].data()),
                       temp1);
    }
  } else {
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

    std::uint32_t* enc_ptr =
        reinterpret_cast<std::uint32_t*>(enc_round_keys.data());
    std::size_t enc_ptr_offset = 0;
    // Round 0 (Original Key)
    enc_ptr_offset += 0;
    __m128i temp1 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset));
    enc_ptr_offset += 2;
    __m128i temp2 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset));
    enc_ptr_offset += 4;

    for (int i = 1; i < 8; ++i) {
      std::cout << "i:" << i << std::endl;
      std::cout << "correct W:" << std::endl
                << util::BytesToHexStr(std::span<std::uint8_t>(
                       reinterpret_cast<std::uint8_t*>(enc_ptr),
                       (enc_ptr_offset + 6) * 4))
                << std::endl;
      // 1. Assist 연산 수행 (Rcon 적용)
      __m128i assist_val = AESKeygenAssist(temp2, i);
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));

      // 2. 위에서 정의한 로직으로 다음 라운드 키 계산
      // (간소화를 위해 내부 로직 전개)
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));

      _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset),
                       _mm_xor_si128(temp1, assist_val));
      enc_ptr_offset += 4;

      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));

      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp1, 4));

      temp2 = _mm_xor_si128(temp2, assist_val);

      _mm_storel_epi64(reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset),
                       temp2);
      enc_ptr_offset += 2;

      std::cout << "W:" << std::endl
                << util::BytesToHexStr(std::span<std::uint8_t>(
                       reinterpret_cast<std::uint8_t*>(enc_ptr),
                       enc_ptr_offset * 4))
                << std::endl;

      temp1 = _mm_loadu_si128(
          reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset - 6));
      temp2 = _mm_loadu_si128(
          reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset - 4));

      std::cout << "temp1: "
                << util::BytesToHexStr(std::span<std::uint8_t>(
                       reinterpret_cast<std::uint8_t*>(&temp1), 16))
                << std::endl;
      std::cout << "temp2: "
                << util::BytesToHexStr(std::span<std::uint8_t>(
                       reinterpret_cast<std::uint8_t*>(&temp2), 16))
                << std::endl;
    }
    // 1. Assist 연산 수행 (Rcon 적용)
    __m128i assist_val = AESKeygenAssist(temp2, 8);

    // 2. 위에서 정의한 로직으로 다음 라운드 키 계산
    // (간소화를 위해 내부 로직 전개)
    __m128i temp = temp1;
    assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4));
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4));
    temp = _mm_xor_si128(temp, _mm_slli_si128(temp, 4));
    temp = _mm_xor_si128(temp, assist_val);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(enc_ptr + enc_ptr_offset),
                     temp);
  }

  for (int i = 1; i < Nr; ++i) {
    reinterpret_cast<__m128i*>(dec_round_keys.data())[i] =
        _mm_aesimc_si128(reinterpret_cast<__m128i*>(enc_round_keys.data())[i]);
  }
  dec_round_keys[0] = enc_round_keys[0];
  dec_round_keys[Nr] = enc_round_keys[Nr];
  return;
}

inline std::uint32_t AES_NI::SubWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = S_box(word_ptr[0]);
  result_ptr[1] = S_box(word_ptr[1]);
  result_ptr[2] = S_box(word_ptr[2]);
  result_ptr[3] = S_box(word_ptr[3]);

  return result;
}

inline std::uint32_t AES_NI::RotWord(const std::uint32_t word) noexcept {
  std::uint32_t result;
  const std::uint8_t* word_ptr = reinterpret_cast<const std::uint8_t*>(&word);
  std::uint8_t* result_ptr = reinterpret_cast<std::uint8_t*>(&result);

  result_ptr[0] = word_ptr[1];
  result_ptr[1] = word_ptr[2];
  result_ptr[2] = word_ptr[3];
  result_ptr[3] = word_ptr[0];

  return result;
}

constexpr std::uint8_t AES_NI::Rcon(const std::uint32_t i) noexcept {
  if (Rcon_memo[i] != static_cast<std::uint8_t>(0x00)) return Rcon_memo[i];

  for (int j = Rcon_memo_index + 1; j <= i; j++) {
    Rcon_memo[j] = gf_mul(Rcon_memo[j - 1], static_cast<std::uint8_t>(0x02));
  }

  Rcon_memo_index = i;

  return Rcon_memo[i];
}

std::array<std::uint8_t, 14> AES_NI::Rcon_memo = {
    static_cast<std::uint8_t>(0x00), static_cast<std::uint8_t>(0x01),
    static_cast<std::uint8_t>(0x02)};
int AES_NI::Rcon_memo_index = 1;

std::uint8_t AES_NI::S_box(std::uint8_t x) {
  uint8_t y = gf_inv(x);

  uint8_t s = y ^ rotl8(y, 1) ^ rotl8(y, 2) ^ rotl8(y, 3) ^ rotl8(y, 4) ^ 0x63;

  return s;
}

}  // namespace bedrock::cipher