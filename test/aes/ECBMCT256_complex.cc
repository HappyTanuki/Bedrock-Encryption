#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AesEcb, 32>(
      "ECBMCT256", "aesmct_intermediate", "complex");
}
