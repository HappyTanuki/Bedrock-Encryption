#include "encryption/util/helper.h"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <vector>

namespace bedrock::cipher::util {

std::vector<std::byte> StrToBytes(const std::string& s) {
  std::vector<std::byte> result(s.size());
  std::memcpy(result.data(), s.data(), s.size());
  return result;
}

std::string BytesToStr(const std::vector<std::byte>& bytes) {
  std::ostringstream osstream;
  for (auto b : bytes) {
    osstream << static_cast<char>(b);
  }
  return osstream.str();
}

std::string BytesToHexStr(const std::span<const std::byte> bytes) {
  std::ostringstream osstream;

  for (auto b : bytes) {
    osstream << std::uppercase << std::setw(2) << std::setfill('0') << std::hex
             << std::to_integer<int>(b);
  }

  return osstream.str();
}

std::vector<std::byte> HexStrToBytes(const std::string& hex) {
  std::vector<std::byte> bytes;
  bytes.reserve(hex.size() / 2);

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::byte byte =
        static_cast<std::byte>(std::stoul(hex.substr(i, 2), nullptr, 16));
    bytes.push_back(byte);
  }

  return bytes;
}

std::vector<std::byte> XorBytes(const std::span<const std::byte> a,
                                const std::span<const std::byte> b) {
  std::vector<std::byte> result((std::max)(a.size(), b.size()));

  std::size_t i = 0;
  for (i = 0; i < (std::min)(a.size(), b.size()); ++i) {
    result[i] = static_cast<std::byte>(static_cast<std::uint8_t>(a[i]) ^
                                       static_cast<std::uint8_t>(b[i]));
  }
  if (a.size() >= b.size()) {
    for (i = i; i < result.size(); ++i) {
      result[i] =
          static_cast<std::byte>(static_cast<std::uint8_t>(a[i]) ^ 0x00);
    }
  } else {
    result[i] = static_cast<std::byte>(0x00 ^ static_cast<std::uint8_t>(b[i]));
  }
  return result;
}

void XorInplace(std::span<std::byte> a, const std::span<const std::byte> b) {
  std::uint32_t size = (std::max)(a.size(), b.size());

  std::size_t i = 0;
  for (i = 0; i < (std::min)(a.size(), b.size()); ++i) {
    a[i] = static_cast<std::byte>(static_cast<std::uint8_t>(a[i]) ^
                                  static_cast<std::uint8_t>(b[i]));
  }
  if (a.size() >= b.size()) {
    for (i = i; i < size; ++i) {
      a[i] = static_cast<std::byte>(static_cast<std::uint8_t>(a[i]) ^ 0x00);
    }
  } else {
    a[i] = static_cast<std::byte>(0x00 ^ static_cast<std::uint8_t>(b[i]));
  }
}

void StandardIncrement(std::span<std::byte> bytes, const int m) {
  std::uint32_t counter_bytes = (m + 7) / 8;
  bool carry = false;

  int i = bytes.size() - 1;
  do {
    if (bytes[i] != static_cast<std::byte>(0xFF)) {
      std::uint8_t t = std::to_integer<std::uint8_t>(bytes[i]);
      t += 1;
      bytes[i] = static_cast<std::byte>(t);
    } else {
      bytes[i] = static_cast<std::byte>(0x00);
      carry = true;
    }
  } while (carry && --i > counter_bytes);
}

std::vector<std::byte> UInt8ToBytesVector(uint64_t value) {
  std::vector<std::byte> result(1);
  result[0] = static_cast<std::byte>(value & 0xFF);
  return result;
}

std::vector<std::byte> UInt32ToBytesVector(uint64_t value) {
  std::vector<std::byte> result(4);
  for (size_t i = 0; i < 4; ++i) {
    result[3 - i] = static_cast<std::byte>(value & 0xFF);
    value >>= 8;
  }
  return result;
}

std::vector<std::byte> Leftmost(const std::vector<std::byte>& value,
                                const std::uint64_t& size) {
  std::vector<std::byte> result;
  size_t byteLen = (std::min)((size + 7) / 8, value.size());
  result.resize(byteLen);
  std::memcpy(result.data(), value.data(), byteLen);

  std::uint32_t extraBits = size % 8;
  if (extraBits != 0) {
    // 예: extraBits = 3 → 상위 3비트만 남기고 나머지는 0으로
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - extraBits));
    result.back() &= static_cast<std::byte>(mask);
  }

  return result;
}

// incomplete, only for size multiple of 8
std::vector<std::byte> Rightmost(const std::vector<std::byte>& value,
                                 const std::uint64_t& size) {
  std::vector<std::byte> result;
  result.resize(size / 8);

  std::uint32_t offset = std::max<size_t>(value.size() - size / 8, 0);

  std::memcpy(result.data(), value.data() + offset, size / 8);

  return result;
}

std::string GetEnglishNumberSufix(std::uint64_t number) {
  std::string result;
  if (number % 10 == 1 && number != 11) {
    result = "st";
  } else if (number % 10 == 2 && number != 12) {
    result = "nd";
  } else if (number % 10 == 3 && number != 13) {
    result = "rd";
  } else {
    result = "th";
  }

  return result;
}

}  // namespace bedrock::cipher::util