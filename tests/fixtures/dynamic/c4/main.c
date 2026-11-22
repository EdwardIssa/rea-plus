#include <stdio.h>
#include <stdlib.h>
static void cleanup_handler(void) { puts("MARK:cleanup_handler"); puts("cleanup-done"); }
int main(void) {
  puts("MARK:main");
  atexit(cleanup_handler);
  puts("body-done");
  return 0;
}
