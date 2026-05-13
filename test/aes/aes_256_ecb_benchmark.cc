#include "common/benchmark_runner.h"

int main() {
  return bedrock::test::RunAesBenchmark<bedrock::cipher::AesEcb, 32>();
}
