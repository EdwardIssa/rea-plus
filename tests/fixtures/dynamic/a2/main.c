#include <stdio.h>
#include <stddef.h>
static const unsigned char blob[] = { 115, 69, 59, 181, 126, 26, 41, 166, 114, 69, 63, 183, 60, 67, 45, 172 };
static const unsigned char key[] = { 17, 55, 90, 195 };
static void unwrap(void) {
  char buf[32];
  size_t n = sizeof(blob);
  size_t i;
  for (i = 0; i < n; i++) buf[i] = (char)(blob[i] ^ key[i % 4]);
  buf[n] = '\0';
  puts("MARK:unwrap");
  puts(buf);
}
int main(void) { puts("MARK:main"); unwrap(); return 0; }
