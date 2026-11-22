#include <stdio.h>
#include <dlfcn.h>
int main(void) {
  char path[64];
  void *h;
  void (*greet)(void);
  puts("MARK:main");
  snprintf(path, sizeof(path), "./lib%s%s.so", "plug", "3");
  h = dlopen(path, RTLD_NOW);
  if (h == 0) return 1;
  greet = (void (*)(void))dlsym(h, "plug_greet");
  if (greet == 0) return 2;
  greet();
  return 0;
}
