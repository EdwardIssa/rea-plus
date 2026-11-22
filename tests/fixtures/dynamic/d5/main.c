#include <stdio.h>
#include <stddef.h>
static const unsigned char blob[] = { 1, 103, 1, 111, 1, 108, 1, 102, 1, 45, 1, 100, 1, 101, 1, 99, 1, 111, 1, 109, 1, 112, 1, 114, 1, 101, 2, 115, 1, 101, 1, 100, 1, 45, 1, 98, 1, 97, 2, 110, 1, 101, 1, 114 };
static void inflate_rle(void) {
  char buf[64];
  size_t i, o = 0;
  for (i = 0; i + 1 < sizeof(blob); i += 2) {
    unsigned int count = blob[i];
    unsigned int k;
    for (k = 0; k < count; k++) buf[o++] = (char)blob[i + 1];
  }
  buf[o] = '\0';
  puts("MARK:inflate_rle");
  puts(buf);
}
int main(void) { puts("MARK:main"); inflate_rle(); return 0; }
