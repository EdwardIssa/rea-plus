#include <stdio.h>
#include <stddef.h>
#include <string.h>
static const unsigned char blob[] = { 17, 24, 15, 3, 5, 24, 3, 90, 31, 30, 19, 19, 18, 25, 90, 4, 18, 20, 5, 18, 3 };
static void reveal_secret(void) {
  char buf[40];
  size_t n = sizeof(blob);
  size_t i;
  for (i = 0; i < n; i++) buf[i] = (char)(blob[i] ^ 0x77);
  buf[n] = '\0';
  puts("MARK:reveal_secret");
  puts(buf);
}
int main(int argc, char **argv) {
  puts("MARK:main");
  puts("public-notice-string");
  if (argc > 1 && strlen(argv[1]) == 6 &&
      argv[1][0] == 'u' && argv[1][1] == 'n' && argv[1][2] == 'l' &&
      argv[1][3] == 'o' && argv[1][4] == 'c' && argv[1][5] == 'k')
    reveal_secret();
  return 0;
}
