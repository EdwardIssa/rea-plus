#include <stdio.h>
struct Ops { void (*open)(void); void (*close)(void); };
static void std_open(void) { puts("MARK:std_open"); puts("std-open"); }
static void std_close(void) { puts("MARK:std_close"); puts("std-close"); }
static void alt_open(void) { puts("MARK:alt_open"); puts("alt-open"); }
static void alt_close(void) { puts("MARK:alt_close"); puts("alt-close"); }
static void direct_helper(void) { puts("MARK:direct_helper"); puts("direct-done"); }
static const struct Ops sets[2] = {
  { std_open, std_close },
  { alt_open, alt_close }
};
int main(int argc, char **argv) {
  int idx = 0;
  const struct Ops *ops;
  puts("MARK:main");
  if (argc > 1 && argv[1][0] == '1') idx = 1;
  ops = &sets[idx];
  ops->open();
  direct_helper();
  ops->close();
  return 0;
}
