#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AES_ECB, 24>(
      "ECBMCT192", "aesmct", "simple");
}
