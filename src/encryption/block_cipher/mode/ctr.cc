#include "encryption/block_cipher/mode/ctr.h"

#include "encryption/util/helper.h"

namespace bedrock::cipher::op_mode {

CTR::CTR(std::unique_ptr<BlockCipherAlgorithm> algorithm,
         const std::span<const std::uint8_t> IV, std::uint32_t m_bits)
    : OperationMode(std::move(algorithm), IV), m(m_bits) {
  std::uint32_t block_bits = cipher->GetBlockSize();
  std::uint32_t block_bytes = block_bits / 8;

  if (m_bits == 0 || m_bits > block_bits) {
    valid = false;
    return;
  }

  std::uint32_t counter_bytes = (m_bits + 7) / 8;

  for (std::uint32_t i = block_bytes - 1; i > block_bytes - counter_bytes;
       i--) {
    this->prev_vector[i] = static_cast<std::uint8_t>(0x00);
    m_bits -= 8;
  }
  this->prev_vector[block_bytes - counter_bytes] &=
      static_cast<std::uint8_t>(0xFF << m_bits);

  valid = true;
}

BlockCipherErrorStatus CTR::Process(const std::span<const std::uint8_t> input,
                                    std::span<std::uint8_t> output) {
  std::uint32_t block_size = cipher->GetBlockSize() / 8;
  if (!IsValid() || !cipher->IsValid() || input.size() != block_size ||
      output.size() != block_size) {
    return BlockCipherErrorStatus::kFailure;
  }

  this->cipher->Encrypt(this->prev_vector, buffer);
  bedrock::util::StandardIncrement(this->prev_vector, m);

  std::copy(buffer.begin(), buffer.end(), output.begin());
  bedrock::util::XorInplace(output, input);

  return BlockCipherErrorStatus::kSuccess;
}

}  // namespace bedrock::cipher::op_mode