#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AES_ECB, 32>(
      "ECBVarKey256");
}
