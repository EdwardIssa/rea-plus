#include <stdio.h>
#include <stdlib.h>
static int marked = 0;
static int cmp_items(const void *a, const void *b) {
  if (!marked) { marked = 1; puts("MARK:cmp_items"); }
  return *(const int *)a - *(const int *)b;
}
int main(void) {
  int values[5] = { 5, 2, 9, 1, 7 };
  char line[64];
  int i, o = 0;
  const char *prefix = "sorted-";
  puts("MARK:main");
  qsort(values, 5, sizeof(int), cmp_items);
  while (*prefix) line[o++] = *prefix++;
  for (i = 0; i < 5; i++) {
    if (i) line[o++] = '-';
    line[o++] = (char)('0' + values[i]);
  }
  line[o] = '\0';
  puts(line);
  return 0;
}
