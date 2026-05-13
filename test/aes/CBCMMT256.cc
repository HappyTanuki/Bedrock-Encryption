#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AesCbc, 32>("CBCMMT256",
                                                                "aesmmt");
}
