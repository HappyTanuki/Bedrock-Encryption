#include "encryption/interfaces.h"

namespace bedrock::cipher {

BlockCipherAlgorithm::~BlockCipherAlgorithm() noexcept = default;

BlockCipherCTX::~BlockCipherCTX() = default;

};  // namespace bedrock::cipher