#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AesEcb, 16>("ECBGFSbox128");
}
