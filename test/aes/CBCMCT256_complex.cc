#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AES_CBC, 32>(
      "CBCMCT256", "aesmct_intermediate", "complex");
}
