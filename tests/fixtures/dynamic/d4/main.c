#include <stdio.h>
#include <unistd.h>
static void root_path(void) { puts("MARK:root_path"); puts("uid-root-path"); }
static void user_path(void) { puts("MARK:user_path"); puts("uid-user-path"); }
int main(void) {
  puts("MARK:main");
  if (getuid() == 0) root_path();
  else user_path();
  return 0;
}
