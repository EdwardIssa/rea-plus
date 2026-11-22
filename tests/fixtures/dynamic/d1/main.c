#include <stdio.h>
#include <unistd.h>
static void branch_true(void) { puts("MARK:branch_true"); puts("path-true"); }
static void branch_false(void) { puts("MARK:branch_false"); puts("path-false"); }
static void choose(void) {
  long x = (long)getpid();
  puts("MARK:choose");
  if ((x * x - x) % 2 == 0) branch_true();
  else branch_false();
}
int main(void) { puts("MARK:main"); choose(); return 0; }
