#include <stdio.h>
#include <string.h>
static const char stored[] = "NCgoLC9mc3M4OTAoPXI5JD0xLDA5cjUyKDkuMj0wczo5OTg=";
static int b64val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}
static void fetch_url(void) {
  unsigned char raw[128];
  char out[128];
  size_t n = strlen(stored);
  size_t i, o = 0;
  for (i = 0; i + 3 < n; i += 4) {
    int a = b64val(stored[i]), b = b64val(stored[i + 1]);
    int c = b64val(stored[i + 2]), d = b64val(stored[i + 3]);
    raw[o++] = (unsigned char)((a << 2) | (b >> 4));
    if (stored[i + 2] != '=') raw[o++] = (unsigned char)(((b & 15) << 4) | (c >> 2));
    if (stored[i + 3] != '=') raw[o++] = (unsigned char)(((c & 3) << 6) | d);
  }
  for (i = 0; i < o; i++) out[i] = (char)(raw[i] ^ 0x5C);
  out[o] = '\0';
  puts("MARK:fetch_url");
  puts(out);
}
int main(void) { puts("MARK:main"); fetch_url(); return 0; }
