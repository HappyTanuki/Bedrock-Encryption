#include "encryption/util/helper.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

#include "common/intrinsics.h"

namespace bedrock::util {

static bool Sse2Enabled() {
  static bedrock::intrinsic::Register reg =
      bedrock::intrinsic::GetCPUFeatures();
  static bool enabled = bedrock::intrinsic::IsCpuEnabledFeature(reg, "SSE2");
  return enabled;
}

std::vector<std::uint8_t> StrToBytes(const std::string& s) {
  std::vector<std::uint8_t> result(s.size());
  std::memcpy(result.data(), s.data(), s.size());
  return result;
}

std::string BytesToHexStr(const std::span<const std::uint8_t> bytes) {
  std::ostringstream osstream;

  for (auto b : bytes) {
    osstream << std::uppercase << std::setw(2) << std::setfill('0') << std::hex
             << static_cast<int>(b);
  }

  return osstream.str();
}

std::vector<std::uint8_t> HexStrToBytes(const std::string& hex) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::uint8_t byte =
        static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::vector<std::uint8_t> XorBytes(const std::span<const std::uint8_t> a,
                                   const std::span<const std::uint8_t> b) {
  const std::size_t max_size = (std::max)(a.size(), b.size());
  const std::size_t min_size = (std::min)(a.size(), b.size());
  std::vector<std::uint8_t> result(max_size);
  std::size_t offset = 0;

  if (a.size() >= b.size()) {
    std::copy(a.begin(), a.end(), result.begin());
  } else {
    std::copy(b.begin(), b.end(), result.begin());
  }

  if (Sse2Enabled()) {
    for (; offset + 16 <= min_size; offset += 16) {
      __m128i _mm_a =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.data() + offset));
      __m128i _mm_b =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.data() + offset));
      __m128i _mm_result = _mm_xor_si128(_mm_a, _mm_b);

      _mm_storeu_si128(reinterpret_cast<__m128i*>(result.data() + offset),
                       _mm_result);
    }
  }

  for (; offset < min_size; ++offset) {
    result[offset] =
        static_cast<std::uint8_t>(static_cast<std::uint8_t>(a[offset]) ^
                                  static_cast<std::uint8_t>(b[offset]));
  }

  return result;
}

void XorInplace(std::span<std::uint8_t> a,
                const std::span<const std::uint8_t> b) {
  const std::size_t min_size = (std::min)(a.size(), b.size());
  std::size_t offset = 0;

  if (Sse2Enabled()) {
    for (; offset + 16 <= min_size; offset += 16) {
      __m128i _mm_a =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(a.data() + offset));
      __m128i _mm_b =
          _mm_loadu_si128(reinterpret_cast<const __m128i*>(b.data() + offset));
      __m128i _mm_result = _mm_xor_si128(_mm_a, _mm_b);

      _mm_storeu_si128(reinterpret_cast<__m128i*>(a.data() + offset),
                       _mm_result);
    }
  }

  for (; offset < min_size; ++offset) {
    a[offset] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(a[offset]) ^
                                          static_cast<std::uint8_t>(b[offset]));
  }
}

void StandardIncrement(std::span<std::uint8_t> bytes, const std::size_t m) {
  std::size_t counter_bytes = (m + 7) / 8;
  std::size_t offset_bits = counter_bytes * 8 - m;
  std::size_t base = bytes.size() - counter_bytes;

  if (bytes[bytes.size() - 1] + 1 < bytes[bytes.size() - 1]) {
    // 캐리 발생
    bytes[bytes.size() - 1] = static_cast<std::uint8_t>(
        bytes[bytes.size() - 1] & (0xFF >> (8 - offset_bits)));
    for (std::size_t i = bytes.size() - 2; i > 0; i--) {
      if (bytes[i] != 0xFF) {
        bytes[i] = static_cast<std::uint8_t>(bytes[i]) + 1;
        break;
      } else {
        bytes[i] = static_cast<std::uint8_t>(0x00);
      }
    }
  } else {
    bytes[bytes.size() - 1] =
        static_cast<std::uint8_t>(bytes[bytes.size() - 1] + 1);
  }
}

std::string GetEnglishNumberSufix(std::uint64_t number) {
  auto m100 = number % 100;
  if (m100 >= 11 && m100 <= 13) return "th";

  switch (number % 10) {
    case 1:
      return "st";
    case 2:
      return "nd";
    case 3:
      return "rd";
    default:
      return "th";
  }
}

}  // namespace bedrock::util