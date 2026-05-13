#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AesCbc, 16>("CBCMMT128",
                                                                "aesmmt");
}
