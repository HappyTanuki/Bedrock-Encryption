#include "common/kat_runner.h"

int main() {
  return bedrock::test::RunKatTest<bedrock::cipher::AES_CBC, 16>(
      "CBCVarTxt128");
}
