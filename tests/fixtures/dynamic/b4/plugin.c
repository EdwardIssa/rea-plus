#include <stdio.h>
static void plug_handler(void) { puts("MARK:plug_handler"); puts("plug-four-hello"); }
static void (*slot)(void) = 0;
__attribute__((constructor)) static void plug_init(void) { slot = plug_handler; }
void (*plug_get_handler(void))(void) {
  puts("MARK:plug_get_handler");
  return slot;
}
