#include <stdio.h>
#include <dlfcn.h>
int main(int argc, char **argv) {
  void *h;
  void (*greet)(void);
  const char *path = "./libplugA.so";
  puts("MARK:main");
  if (argc > 1 && argv[1][0] == 'b') path = "./libplugB.so";
  h = dlopen(path, RTLD_NOW);
  if (h == 0) return 1;
  greet = (void (*)(void))dlsym(h, "plug_greet");
  if (greet == 0) return 2;
  greet();
  return 0;
}
