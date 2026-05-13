#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AES_ECB, 16>(
      "ECBMCT128", "aesmct_intermediate", "complex");
}
