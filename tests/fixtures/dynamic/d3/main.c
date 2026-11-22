#include <stdio.h>
static void path_red(void) { puts("MARK:path_red"); puts("color-red"); }
static void path_blue(void) { puts("MARK:path_blue"); puts("color-blue"); }
static void path_none(void) { puts("MARK:path_none"); puts("color-none"); }
int main(int argc, char **argv) {
  char c = argc > 1 ? argv[1][0] : '\0';
  puts("MARK:main");
  if (c == 'r') path_red();
  else if (c == 'b') path_blue();
  else path_none();
  return 0;
}
