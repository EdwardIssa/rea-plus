#include <stdio.h>
#include <stddef.h>
static const unsigned char blob[] = { 35, 46, 50, 42, 35, 111, 49, 39, 33, 48, 39, 54, 111, 45, 44, 39 };
static void reveal(void) {
  char buf[32];
  size_t n = sizeof(blob);
  size_t i;
  for (i = 0; i < n; i++) buf[i] = (char)(blob[i] ^ 0x42);
  buf[n] = '\0';
  puts("MARK:reveal");
  puts(buf);
}
int main(void) { puts("MARK:main"); reveal(); return 0; }
