#include <stdio.h>
static void op_add(void) { puts("MARK:op_add"); puts("result-add"); }
static void op_sub(void) { puts("MARK:op_sub"); puts("result-sub"); }
static void op_mul(void) { puts("MARK:op_mul"); puts("result-mul"); }
static void (*table[3])(void) = { op_add, op_sub, op_mul };
int main(int argc, char **argv) {
  int idx = 0;
  puts("MARK:main");
  if (argc > 1 && argv[1][0] >= '0' && argv[1][0] <= '2') idx = argv[1][0] - '0';
  table[idx]();
  return 0;
}
