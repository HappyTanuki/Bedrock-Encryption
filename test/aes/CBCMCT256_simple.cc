#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AesCbc, 32>(
      "CBCMCT256", "aesmct", "simple");
}
