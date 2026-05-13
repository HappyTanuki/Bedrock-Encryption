#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AES_CBC, 24>(
      "CBCMCT192", "aesmct", "simple");
}
