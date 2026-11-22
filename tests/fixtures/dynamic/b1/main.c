#include <stdio.h>
#include <dlfcn.h>
int main(void) {
  void *h;
  void (*greet)(void);
  puts("MARK:main");
  h = dlopen("./libplug1.so", RTLD_NOW);
  if (h == 0) return 1;
  greet = (void (*)(void))dlsym(h, "plug_greet");
  if (greet == 0) return 2;
  greet();
  return 0;
}
