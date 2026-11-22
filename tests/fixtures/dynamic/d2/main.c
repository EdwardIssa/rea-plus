#include <stdio.h>
#include <stdlib.h>
static void feature_on(void) { puts("MARK:feature_on"); puts("feature-enabled"); }
static void feature_off(void) { puts("MARK:feature_off"); puts("feature-disabled"); }
int main(void) {
  puts("MARK:main");
  if (getenv("FEATURE_X") != 0) feature_on();
  else feature_off();
  return 0;
}
