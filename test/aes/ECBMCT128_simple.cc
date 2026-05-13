#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AesEcb, 16>(
      "ECBMCT128", "aesmct", "simple");
}
