#include "common/mct_runner.h"

int main() {
  return bedrock::test::RunMctTest<bedrock::cipher::AES_CBC, 16>(
      "CBCMCT128", "aesmct", "simple");
}
