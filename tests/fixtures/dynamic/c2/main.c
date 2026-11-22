#include <stdio.h>
static void op_xor(void) { puts("MARK:op_xor"); puts("result-xor"); }
static void op_and(void) { puts("MARK:op_and"); puts("result-and"); }
static void op_or(void) { puts("MARK:op_or"); puts("result-or"); }
static void (*table[3])(void) = { op_xor, op_and, op_or };
int main(int argc, char **argv) {
  unsigned int h = 0;
  const char *s = argc > 1 ? argv[1] : "";
  puts("MARK:main");
  while (*s) { h += (unsigned char)*s; s++; }
  table[h % 3]();
  return 0;
}
