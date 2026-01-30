#include <iostream>

#include "encryption/util/helper.h"

// m-bit 정수를 big-endian byte 배열로 변환
static void WriteCounter(std::span<std::uint8_t> bytes, uint64_t m,
                         uint64_t value) {
  size_t n = (m + 7) / 8;
  size_t base = bytes.size() - n;

  for (size_t i = 0; i < n; ++i) {
    bytes[base + n - 1 - i] = static_cast<std::uint8_t>(value & 0xFF);
    value >>= 8;
  }

  size_t offset = n * 8 - m;
  uint8_t mask = 0xFFu >> offset;

  uint8_t v = bytes[base];
  bytes[base] = static_cast<std::uint8_t>(v & mask);
}

// byte 배열에서 m-bit 정수 읽기
static uint64_t ReadCounter(std::span<std::uint8_t> bytes, uint64_t m) {
  size_t n = (m + 7) / 8;
  size_t base = bytes.size() - n;

  uint64_t v = 0;
  for (size_t i = 0; i < n; ++i) {
    v = (v << 8) | bytes[base + i];
  }

  v &= ((static_cast<uint64_t>(1) << m) - 1);

  return v;
}

static bool RunTest(uint64_t m, int steps) {
  std::vector<std::uint8_t> buf(8);
  uint64_t mod = (m == 64) ? 0 : (static_cast<uint64_t>(1) << m);

  uint64_t ref = 0;
  WriteCounter(buf, m, ref);

  for (int i = 0; i < steps; ++i) {
    bedrock::util::StandardIncrement(buf, m);

    ref = (ref + 1) % mod;
    uint64_t got = ReadCounter(buf, m);

    if (got != ref) {
      std::cout << "FAIL  m=" << m << " step=" << i << " expected=" << ref
                << " got=" << got << "\n";
      return true;
    }
  }

  std::cout << "PASS  m=" << m << "\n";

  return false;
}

int main() {
  if (RunTest(1, 10)) {
    return 0;
  }
  if (RunTest(7, 10)) {
    return 0;
  }
  if (RunTest(8, 10)) {
    return 0;
  }
  if (RunTest(9, 10)) {
    return 0;
  }
  if (RunTest(13, 10)) {
    return 0;
  }
  if (RunTest(16, 10)) {
    return 0;
  }
  if (RunTest(31, 10)) {
    return 0;
  }
  if (RunTest(32, 10)) {
    return 0;
  }

  std::cout << "ALL TESTS PASSED\n";
}
