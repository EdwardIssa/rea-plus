#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void) {
  void *chunks[64];
  int i;
  for (i = 0; i < 64; i++) {
    chunks[i] = malloc(256u << 20);
    if (chunks[i] == 0) return 1;
    memset(chunks[i], 1, 256u << 20);
    puts("chunk");
  }
  for (;;) pause();
  return 0;
}
