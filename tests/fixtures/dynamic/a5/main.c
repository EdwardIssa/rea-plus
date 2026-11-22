#include <stdio.h>
static void assemble(void) {
  char buf[24];
  buf[0] = 'e'; buf[1] = 'c'; buf[2] = 'h'; buf[3] = 'o'; buf[4] = '-';
  buf[5] = 's'; buf[6] = 't'; buf[7] = 'a'; buf[8] = 'c'; buf[9] = 'k';
  buf[10] = '-'; buf[11] = 's'; buf[12] = 'e'; buf[13] = 'c'; buf[14] = 'r';
  buf[15] = 'e'; buf[16] = 't'; buf[17] = '\0';
  puts("MARK:assemble");
  puts(buf);
}
int main(void) { puts("MARK:main"); assemble(); return 0; }
