#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AesEcb, 24>(
      "ECBMCT192", "aesmct_intermediate", "complex");
}
