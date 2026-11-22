#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main(void) {
  pid_t p = fork();
  if (p == 0) {
    pid_t q = fork();
    if (q == 0) {
      setsid();
      for (;;) pause();
    }
    _exit(0);
  }
  puts("escapee-spawned");
  return 0;
}
