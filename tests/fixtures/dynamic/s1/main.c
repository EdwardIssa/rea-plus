#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
int main(void) {
  char *first = malloc(16u << 20);
  if (first) memset(first, 1, 16u << 20);
  for (;;) {
    pid_t p = fork();
    if (p == 0) {
      char *m = malloc(16u << 20);
      if (m) memset(m, 1, 16u << 20);
      for (;;) pause();
    }
  }
  return 0;
}
