#ifndef BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_HELPER_H_
#define BEDROCK_ENCRYPTION_ENCRYPTION_UTIL_HELPER_H_

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace bedrock::util {

std::vector<std::uint8_t> StrToBytes(const std::string& s);

std::string BytesToHexStr(const std::span<const std::uint8_t> bytes);

std::vector<std::uint8_t> HexStrToBytes(const std::string& hex);
template <std::uint32_t Size>
std::array<std::uint8_t, Size> HexStrToBytes(const std::string& hex);

std::vector<std::uint8_t> XorBytes(const std::span<const std::uint8_t> a,
                                   const std::span<const std::uint8_t> b);
void XorInplace(std::span<std::uint8_t> a,
                const std::span<const std::uint8_t> b);

void StandardIncrement(std::span<std::uint8_t> bytes, const std::size_t m);

inline std::vector<std::uint8_t> MaskSeedlen(const std::vector<std::uint8_t>& v,
                                             const std::size_t seedlen_bits);

template <typename... Vectors>
std::vector<std::uint8_t> AddByteVectors(const Vectors&... vecs);

template <typename... Vectors>
std::vector<std::uint8_t> ConcatByteVectors(const Vectors&... vecs);

std::string GetEnglishNumberSufix(std::uint64_t number);

template <std::uint32_t Size>
std::array<std::uint8_t, Size> HexStrToBytes(const std::string& hex) {
  std::array<std::uint8_t, Size> bytes = {};

  for (size_t i = 0; i < hex.size(); i += 2) {
    bytes[i / 2] =
        static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
  }

  return bytes;
}

inline std::vector<std::uint8_t> MaskSeedlen(const std::vector<std::uint8_t>& v,
                                             const std::size_t seedlen_bits) {
  std::size_t byteLen = (seedlen_bits + 7) / 8;
  // 결과는 하위(byteLen) 바이트를 취함 (rightmost)
  std::vector<std::uint8_t> res;
  if (v.size() <= byteLen) {
    // v가 짧으면 좌측(상위) 0으로 패딩하여 길이 맞춤
    res.assign(byteLen - v.size(), static_cast<std::uint8_t>(0));
    res.insert(res.end(), v.begin(), v.end());
  } else {
    // v가 길면 오른쪽 끝에서 byteLen 바이트를 복사
    res.resize(byteLen);
    auto offset = static_cast<std::ptrdiff_t>(v.size() - byteLen);
    std::copy(v.begin() + offset, v.end(), res.begin());
  }
  // seedlen이 바이트 정렬이 아닌 경우(즉 extraBits != 0) :
  // res[0]의 상위(왼쪽) 비트들만 남기고 나머지 비트는 0으로
  std::size_t extraBits = seedlen_bits % 8;
  if (extraBits != 0) {
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - extraBits));
    res[0] =
        static_cast<std::uint8_t>(static_cast<unsigned char>(res[0]) & mask);
  }
  return res;
}

template <typename... Vectors>
std::vector<std::uint8_t> AddByteVectors(const Vectors&... vecs) {
  // span 배열로 가리켜 읽기 전용으로 사용
  std::array<std::span<const std::uint8_t>, sizeof...(vecs)> all = {
      std::span(vecs)...};

  // 결과 바이트 길이 = 가장 긴 입력 길이 (MSB-first 표현을 가정)
  size_t byteLen = 0;
  for (auto v : all) byteLen = (std::max)(byteLen, v.size());

  std::vector<std::uint8_t> result(byteLen);
  unsigned int carry = 0;

  // i는 하위 바이트 오프셋: 0 => LSB (맨 끝)
  for (size_t i = 0; i < byteLen; ++i) {
    unsigned int sum = carry;
    for (auto v : all) {
      if (i < v.size()) {
        // 입력 벡터들은 MSB-first로 저장되어 있다고 가정.
        // LSB 쪽 바이트를 읽으려면 (size-1 - i) 인덱스를 사용.
        sum += static_cast<unsigned int>(
            std::to_integer<unsigned char>(v[v.size() - 1 - i]));
      }
    }
    // 결과는 MSB-first로 유지해야 하므로, LSB부터 채우되
    // 결과의 (byteLen-1 - i) 위치에 쓴다.
    result[byteLen - 1 - i] = static_cast<std::uint8_t>(sum & 0xFF);
    carry = sum >> 8;
  }

  // 최상위 carry가 남으면 앞에 삽입 (MSB-first)
  if (carry) {
    result.insert(result.begin(), static_cast<std::uint8_t>(carry & 0xFF));
  }

  return result;
}

template <typename... Vectors>
std::vector<std::uint8_t> ConcatByteVectors(const Vectors&... vecs) {
  size_t total_size = (vecs.size() + ... + 0);
  std::vector<std::uint8_t> result;
  result.reserve(total_size);
  (result.insert(result.end(), vecs.begin(), vecs.end()), ...);
  return result;
}

}  // namespace bedrock::util

#endif
