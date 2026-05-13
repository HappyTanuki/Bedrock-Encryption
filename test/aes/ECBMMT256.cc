#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AesEcb, 32>("ECBMMT256",
                                                                "aesmmt");
}
