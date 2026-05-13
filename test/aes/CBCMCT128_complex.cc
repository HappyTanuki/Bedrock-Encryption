#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AesCbc, 16>(
      "CBCMCT128", "aesmct_intermediate", "complex");
}
