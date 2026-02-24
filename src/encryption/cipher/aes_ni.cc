#include <emmintrin.h>
#include <immintrin.h>

#include <cassert>
#include <cstring>

#include "encryption/cipher/aes.h"
#include "encryption/util/helper.h"

namespace bedrock::cipher {

AES_NI::~AES_NI() = default;

void AES_NI::EncryptImpl(BlockCipherCTX& ctx,
                         std::span<const std::uint8_t> block,
                         std::span<std::uint8_t> out) const noexcept {
  std::copy(block.begin(), block.end(), ctx.state.begin());

  bedrock::util::XorInplace(ctx.state, ctx.enc_round_keys[0]);

  __m128i state_128i =
      _mm_loadu_si128(reinterpret_cast<const __m128i*>(ctx.state.data()));
  const __m128i* _m128_round_keys =
      reinterpret_cast<const __m128i*>(ctx.enc_round_keys.data());

  for (int round = 1; round < ctx.Nr; round++) {
    state_128i = _mm_aesenc_si128(state_128i, _m128_round_keys[round]);
  }
  state_128i = _mm_aesenclast_si128(state_128i, _m128_round_keys[ctx.Nr]);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(ctx.state.data()), state_128i);

  std::copy(ctx.state.begin(), ctx.state.end(), out.begin());

  return;
}

void AES_NI::DecryptImpl(BlockCipherCTX& ctx,
                         std::span<const std::uint8_t> block,
                         std::span<std::uint8_t> out) const noexcept {
  std::copy(block.begin(), block.end(), ctx.state.begin());

  bedrock::util::XorInplace(ctx.state, ctx.dec_round_keys[ctx.Nr]);

  __m128i state_128i =
      _mm_loadu_si128(reinterpret_cast<__m128i*>(ctx.state.data()));

  for (int round = ctx.Nr - 1; round > 0; --round) {
    state_128i = _mm_aesdec_si128(
        state_128i,
        reinterpret_cast<const __m128i*>(ctx.dec_round_keys.data())[round]);
  }
  state_128i = _mm_aesdeclast_si128(
      state_128i,
      reinterpret_cast<const __m128i*>(ctx.dec_round_keys.data())[0]);

  _mm_storeu_si128(reinterpret_cast<__m128i*>(ctx.state.data()), state_128i);

  std::copy(ctx.state.begin(), ctx.state.end(), out.begin());

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

ErrorStatus AES_NI::KeyExpantion(std::span<const std::uint8_t> key,
                                 BlockCipherCTX& ctx) const noexcept {
  std::uint16_t key_size = key.size() * 8;
  std::uint32_t Nk = key_size / 32;
  std::uint32_t Nr = Nk + 6;

  if (ctx.enc_round_keys.size() < Nr + 1 ||
      ctx.dec_round_keys.size() < Nr + 1) {
    return ErrorStatus::kFailure;
  }

  std::memcpy(ctx.enc_round_keys.data(), key.data(), key.size());

  if (key_size == 256) {
    __m128i temp1 = _mm_loadu_si128(
        reinterpret_cast<__m128i*>(ctx.enc_round_keys[0].data()));
    __m128i temp2 = _mm_loadu_si128(
        reinterpret_cast<__m128i*>(ctx.enc_round_keys[1].data()));

    int i = 2;
    __m128i assist_val = _mm_set_epi32(0, 0, 0, 0);
    while (i < Nr - 1) {
      assist_val = AESKeygenAssist(temp2, i / 2);
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));

      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, assist_val);

      _mm_storeu_si128(
          reinterpret_cast<__m128i*>(ctx.enc_round_keys[i++].data()), temp1);

      assist_val = AESKeygenAssist(temp1, 0);
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(2, 2, 2, 2));

      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, _mm_slli_si128(temp2, 4));
      temp2 = _mm_xor_si128(temp2, assist_val);

      _mm_storeu_si128(
          reinterpret_cast<__m128i*>(ctx.enc_round_keys[i++].data()), temp2);
    }

    assist_val = AESKeygenAssist(temp2, i / 2);
    assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));

    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
    temp1 = _mm_xor_si128(temp1, assist_val);

    _mm_storeu_si128(reinterpret_cast<__m128i*>(ctx.enc_round_keys[i++].data()),
                     temp1);

  } else if (key_size == 128) {
    // Round 0 (Original Key)
    __m128i temp1 =
        _mm_loadu_si128(reinterpret_cast<__m128i*>(ctx.enc_round_keys.data()));

    for (int i = 1; i < Nr + 1; ++i) {
      __m128i assist_val = AESKeygenAssist(temp1, i);

      // 라운드 키 계산
      assist_val = _mm_shuffle_epi32(assist_val, _MM_SHUFFLE(3, 3, 3, 3));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4));
      temp1 = _mm_xor_si128(temp1, assist_val);

      // 결과 저장
      _mm_storeu_si128(reinterpret_cast<__m128i*>(ctx.enc_round_keys[i].data()),
                       temp1);
    }
  } else {
    __m128i x, y, assist;
    uint32_t* W = reinterpret_cast<uint32_t*>(ctx.enc_round_keys.data());

    // 초기 키 로드: x = [W0, W1, W2, W3], y = [W4, W5, ?, ?]
    x = _mm_loadu_si128(reinterpret_cast<const __m128i*>(W));
    y = _mm_loadl_epi64(reinterpret_cast<const __m128i*>(W + 4));

    for (int i = 0; i < 8; ++i) {
      // 1. KeygenAssist: y의 W5(index 1)를 사용하기 위해 셔플
      // _mm_aeskeygenassist는 index 3을 참조하므로 W5를 끝으로 보냄
      __m128i keygen_src = _mm_shuffle_epi32(y, _MM_SHUFFLE(1, 1, 1, 1));
      assist = AESKeygenAssist(keygen_src, i + 1);
      assist = _mm_shuffle_epi32(assist, _MM_SHUFFLE(1, 1, 1, 1));  // 결과 전파

      // 2. W6-W9 계산 (기존 W0-W3인 x와 assist 활용)
      __m128i tmp = _mm_slli_si128(x, 4);
      x = _mm_xor_si128(x, tmp);
      tmp = _mm_slli_si128(tmp, 4);
      x = _mm_xor_si128(x, tmp);
      tmp = _mm_slli_si128(tmp, 4);
      x = _mm_xor_si128(x, tmp);
      x = _mm_xor_si128(x, assist);

      // 3. W10-W11 계산 (기존 W4-W5인 y와 신규 W9 활용)
      __m128i x_last = _mm_shuffle_epi32(x, _MM_SHUFFLE(3, 3, 3, 3));
      y = _mm_xor_si128(y, _mm_slli_si128(y, 4));
      y = _mm_xor_si128(y, x_last);

      // 4. 저장 (Stitching 없이 순차 저장)
      // i=0일 때: W6, W7, W8, W9 저장 (16바이트)
      _mm_storeu_si128(reinterpret_cast<__m128i*>(W + 6 + i * 6), x);
      // i=0일 때: W10, W11 저장 (8바이트)
      if (10 + i * 6 < 52) {
        _mm_storel_epi64(reinterpret_cast<__m128i*>(W + 10 + i * 6), y);
      }

      // 다음 루프를 위한 준비:
      // 현재 x=[W6, W7, W8, W9], y=[W10, W11, ?, ?]
      // 다음 루프에서 x는 "6워드 전"인 W6-W9가 되어야 하고,
      // y는 "6워드 전"인 W10-W11이 되어야 함. (이미 세팅 완료)
    }
  }

  for (int i = 1; i < Nr; ++i) {
    reinterpret_cast<__m128i*>(ctx.dec_round_keys.data())[i] = _mm_aesimc_si128(
        reinterpret_cast<__m128i*>(ctx.enc_round_keys.data())[i]);
  }
  ctx.dec_round_keys[0] = ctx.enc_round_keys[0];
  ctx.dec_round_keys[Nr] = ctx.enc_round_keys[Nr];

  return ErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher