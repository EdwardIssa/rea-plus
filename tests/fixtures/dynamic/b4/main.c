#include <stdio.h>
#include <dlfcn.h>
int main(void) {
  void *h;
  void *(*get_handler)(void);
  void (*handler)(void);
  puts("MARK:main");
  h = dlopen("./libplug4.so", RTLD_NOW);
  if (h == 0) return 1;
  get_handler = (void *(*)(void))dlsym(h, "plug_get_handler");
  if (get_handler == 0) return 2;
  handler = (void (*)(void))get_handler();
  if (handler == 0) return 3;
  handler();
  return 0;
}
