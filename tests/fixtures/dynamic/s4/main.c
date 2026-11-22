#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
/*
 * Containment fixture s4: the escapee changes its image.
 *
 * Same escape shape as s3 (double-fork, then setsid into a new session),
 * but instead of pausing in the target's own image it execs /bin/sleep
 * with a long, distinctive duration (31337 s, chosen so the invocation
 * is identifiable in /proc and collides with nothing else on the host).
 * Consequences for the termination cascade, by construction:
 *   - the process-group kill misses it (setsid put it in a new group);
 *   - the target-exe sweep misses it (its /proc/<pid>/exe is /bin/sleep,
 *     not this binary);
 *   - only the subreaper parentage sweep can reap it: orphaned, it
 *     reparents to the subreaper worker and stays inside the
 *     supervisor's /proc descendant accounting. Without the shim it
 *     reparents to the host init and survives every cascade layer.
 * Harmless by design: the escapee only sleeps.
 */
int main(void) {
  pid_t p = fork();
  if (p == 0) {
    pid_t q = fork();
    if (q == 0) {
      setsid();
      execl("/bin/sleep", "sleep", "31337", (char *)NULL);
      _exit(127);
    }
    _exit(0);
  }
  puts("escapee-spawned");
  return 0;
}
