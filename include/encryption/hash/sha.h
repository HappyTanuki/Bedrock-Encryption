#pragma once
#include <memory>
#include <queue>
#include <cassert>
#include <cstring>
#include <span>

namespace bedrock::hash {

template <std::uint32_t DigestLen>
class SHA : public HashAlgorithm<DigestLen> {
 public:
  SHA();
  std::array<std::byte, DigestLen / 8> Digest(
      std::span<const std::uint8_t> data) const final override;

  void Update(const HashAlgorithmInputData& data) final override;
  std::array<std::byte, DigestLen / 8> Digest() final override;
  void Reset() final override;

 private:
  constexpr std::vector<std::array<std::uint32_t, 16>> Padding(
      const HashAlgorithmInputData& data) const;
  constexpr std::array<std::uint32_t, 16> MakeMessage(
      const std::array<std::byte, 64>& data, std::uint64_t data_bit_length);
  constexpr std::array<std::uint32_t, 8> ProcessMessageBlock(
      const std::array<std::uint32_t, 16>& M,
      const std::array<std::uint32_t, 8>& H) const;

  std::array<std::byte, 64> data_buffer;
  std::uint64_t data_buffer_bit_length = 0;
  std::uint64_t data_length = 0;

  std::array<std::uint32_t, 8> H;

  constexpr std::uint32_t ROTR(std::uint32_t x, std::uint32_t n) const;
  constexpr std::uint32_t Ch(std::uint32_t x, std::uint32_t y,
                             std::uint32_t z) const;
  constexpr std::uint32_t Maj(std::uint32_t x, std::uint32_t y,
                              std::uint32_t z) const;
  constexpr std::uint32_t Sigma0(std::uint32_t x) const;
  constexpr std::uint32_t Sigma1(std::uint32_t x) const;
  constexpr std::uint32_t sigma0(std::uint32_t x) const;
  constexpr std::uint32_t sigma1(std::uint32_t x) const;

  static constexpr std::uint32_t K[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
  static constexpr std::uint32_t H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                          0xa54ff53a, 0x510e527f, 0x9b05688c,
                                          0x1f83d9ab, 0x5be0cd19};
};

template <std::uint32_t DigestLen>
SHA<DigestLen>::SHA() {
  if (DigestLen == 1)
    this->digest_size = 160;
  else
    this->digest_size = DigestLen;
  if (DigestLen >= 384)
    this->inner_block_size = 1024;
  else
    this->inner_block_size = 512;
  Reset();
}

template <std::uint32_t DigestLen>
void SHA<DigestLen>::Reset() {
  std::copy(std::begin(H0), std::end(H0), H.begin());
  data_length = 0;
  data_buffer_bit_length = 0;
}

template <>
constexpr std::uint32_t SHA<256>::ROTR(std::uint32_t x, std::uint32_t n) const {
  return (x >> n) | (x << (32 - n));
}
template <>
constexpr std::uint32_t SHA<256>::Ch(std::uint32_t x, std::uint32_t y,
                                     std::uint32_t z) const {
  return (x & y) ^ (~x & z);
}
template <>
constexpr std::uint32_t SHA<256>::Maj(std::uint32_t x, std::uint32_t y,
                                      std::uint32_t z) const {
  return (x & y) ^ (x & z) ^ (y & z);
}

template <>
constexpr std::uint32_t SHA<256>::Sigma0(std::uint32_t x) const {
  return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}
template <>
constexpr std::uint32_t SHA<256>::Sigma1(std::uint32_t x) const {
  return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}
template <>
constexpr std::uint32_t SHA<256>::sigma0(std::uint32_t x) const {
  return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}
template <>
constexpr std::uint32_t SHA<256>::sigma1(std::uint32_t x) const {
  return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

template <>
constexpr std::vector<std::array<std::uint32_t, 16>> SHA<256>::Padding(
    const HashAlgorithmInputData& data) const {
  std::vector<std::array<std::uint32_t, 16>> padded = {};
  padded.resize((data.bit_length + 1 + 64 + 511) / 512);

  for (int i = 0; i < data.message.size(); i++) {
    padded[i / 64][(i / 4) % 16] |= std::to_integer<uint32_t>(data.message[i])
                                    << 8 * (3 - (i % 4));
  }

  padded[data.bit_length / 512][(data.bit_length / 32) % 16] |=
      (1u << (31 - (data.bit_length % 32)));

  padded.back()[14] = static_cast<uint32_t>(data.bit_length >> 32);
  padded.back()[15] = static_cast<uint32_t>(data.bit_length & 0xFFFFFFFF);

  return padded;
}

template <>
constexpr std::array<std::uint32_t, 16> SHA<256>::MakeMessage(
    const std::array<std::byte, 64>& data, std::uint64_t data_bit_length) {
  std::array<std::uint32_t, 16> M = {};

  for (int i = 0; i < 64 && i < (data_bit_length + 7) / 8; i++) {
    M[i / 4] |= std::to_integer<uint32_t>(data[i]) << 8 * (3 - (i % 4));
  }

  return M;
}

template <>
constexpr std::array<std::uint32_t, 8> SHA<256>::ProcessMessageBlock(
    const std::array<std::uint32_t, 16>& M,
    const std::array<std::uint32_t, 8>& H) const {
  std::array<std::uint32_t, 64> W = {};

  for (int t = 0; t < 16; t++) {
    W[t] = M[t];
  }
  for (int t = 16; t < 64; t++) {
    W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
  }
  std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                g = H[6], h = H[7];
  std::uint32_t T1 = 0, T2 = 0;
  for (int t = 0; t < 64; t++) {
    T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t];
    T2 = Sigma0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
  }

  return {H[0] + a, H[1] + b, H[2] + c, H[3] + d,
          H[4] + e, H[5] + f, H[6] + g, H[7] + h};
}

template <>
inline std::array<std::byte, 32> SHA<256>::Digest(
    const HashAlgorithmInputData& data) const {
  std::vector<std::array<std::uint32_t, 16>> M = Padding(data);

  std::array<std::uint32_t, 8> H = {H0[0], H0[1], H0[2], H0[3],
                                    H0[4], H0[5], H0[6], H0[7]};

  for (int i = 0; i < M.size(); i++) {
    H = ProcessMessageBlock(M[i], H);
  }
  std::array<std::byte, 32> ret;
  for (int i = 0; i < 8; i++) {
    std::uint32_t v = ::htonl(H[i]);
    std::memcpy(ret.data() + i * 4, &v, 4);
  }
  return ret;
}

template <>
inline void SHA<256>::Update(const HashAlgorithmInputData& data) {
  const uint8_t* input_ptr =
      reinterpret_cast<const uint8_t*>(data.message.data());
  size_t input_bits = data.bit_length;

  data_length += input_bits;

  if (data_buffer_bit_length > 0) {
    size_t bits_to_copy = (512 - data_buffer_bit_length) < input_bits
                              ? 512 - data_buffer_bit_length
                              : input_bits;
    size_t bytes_to_copy = (bits_to_copy + 7) / 8;

    std::memcpy(data_buffer.data() + (data_buffer_bit_length / 8), input_ptr,
                bytes_to_copy);
    data_buffer_bit_length += bits_to_copy;

    input_ptr += bytes_to_copy;
    input_bits -= bits_to_copy;

    if (data_buffer_bit_length == 512) {
      H = ProcessMessageBlock(MakeMessage(data_buffer, 512), H);
      data_buffer_bit_length = 0;
    }
  }

  while (input_bits >= 512) {
    std::memcpy(data_buffer.data(), input_ptr, 64);
    H = ProcessMessageBlock(MakeMessage(data_buffer, 512), H);
    input_ptr += 64;
    input_bits -= 512;
  }

  if (input_bits > 0) {
    size_t bytes_remaining = (input_bits + 7) / 8;
    std::memcpy(data_buffer.data(), input_ptr, bytes_remaining);
    data_buffer_bit_length = input_bits;
  }
}

template <>
inline std::array<std::byte, 32> SHA<256>::Digest() {
  std::array<std::uint32_t, 16> M = {};

  M = MakeMessage(data_buffer, data_buffer_bit_length);
  M[(data_buffer_bit_length / 32) % 16] |=
      (1u << (31 - (data_buffer_bit_length % 32)));

  if (data_buffer_bit_length % 512 > 447) {
    H = ProcessMessageBlock(M, H);
    M.fill(0);
  }
  M[14] = static_cast<uint32_t>(data_length >> 32);
  M[15] = static_cast<uint32_t>(data_length & 0xFFFFFFFF);
  H = ProcessMessageBlock(M, H);
  data_buffer_bit_length = 0;

  std::array<std::byte, 32> ret;
  for (int i = 0; i < 8; i++) {
    std::uint32_t v = ::htonl(H[i]);
    std::memcpy(ret.data() + i * 4, &v, 4);
  }

  Reset();

  return ret;
}

};