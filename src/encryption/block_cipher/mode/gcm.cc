#include "encryption/block_cipher/mode/gcm.h"

namespace bedrock::cipher::op_mode {

GCM::GCM(std::unique_ptr<BlockCipherAlgorithm> algorithm,
         const std::span<const std::uint8_t> IV, std::uint32_t m_bits)
    : CTR(std::move(algorithm), IV, m_bits) {}

BlockCipherErrorStatus GCM::Process(const std::span<const std::uint8_t> input,
                                    std::span<std::uint8_t> output) {}

bool GCM::IsValid() const {}

}  // namespace bedrock::cipher::op_mode