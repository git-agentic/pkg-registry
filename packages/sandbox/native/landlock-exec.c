/*
 * landlock-exec: apply a Landlock exec-allow floor, then exec the given command.
 * Invoked as the innermost command inside bwrap:
 *   landlock-exec --allow /bin --allow /usr/bin ... -- /bin/sh -c <script>
 * Grants LANDLOCK_ACCESS_FS_EXECUTE beneath each --allow path; exec of anything
 * outside the floor is then kernel-denied. Restriction is inherited across execve.
 * Self-contained: inlines the Landlock uapi so it needs no kernel headers.
 * SPIKE ARTIFACT (Phase 1). Linux-only; does not compile on macOS.
 */
#define _GNU_SOURCE
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif

#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_RULE_PATH_BENEATH 1
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)

/* ABI v1 ruleset attr: just the fs-access mask. Passing size=8 is accepted on all
 * ABIs (newer kernels zero-fill the rest). */
struct ll_ruleset_attr { unsigned long long handled_access_fs; };
/* Exact 12-byte layout the kernel expects: u64 + s32, no padding. */
struct ll_path_beneath_attr { unsigned long long allowed_access; int parent_fd; } __attribute__((packed));

extern char **environ;

static long ll_create(const void *attr, unsigned long size, unsigned int flags) {
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
static long ll_add(int fd, unsigned int type, const void *attr, unsigned int flags) {
  return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}
static long ll_restrict(int fd, unsigned int flags) {
  return syscall(__NR_landlock_restrict_self, fd, flags);
}

int main(int argc, char **argv) {
  /* Parse: --allow <path> ... -- <cmd> [args...] */
  const char *allows[256];
  int nallow = 0;
  int i = 1;
  for (; i < argc; i++) {
    if (strcmp(argv[i], "--") == 0) { i++; break; }
    if (strcmp(argv[i], "--allow") == 0 && i + 1 < argc) {
      if (nallow < 256) allows[nallow++] = argv[++i];
      else { fprintf(stderr, "landlock-exec: too many --allow entries\n"); return 2; }
    } else {
      fprintf(stderr, "landlock-exec: unexpected arg '%s'\n", argv[i]);
      return 2;
    }
  }
  if (i >= argc) { fprintf(stderr, "landlock-exec: no command after --\n"); return 2; }
  char **cmd = &argv[i];

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("landlock-exec: prctl(NO_NEW_PRIVS)"); return 2; }

  long abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 1) {
    fprintf(stderr, "landlock-exec: Landlock unavailable (abi=%ld errno=%d %s)\n",
            abi, errno, strerror(errno));
    return 3; /* fallback signal */
  }

  struct ll_ruleset_attr rattr;
  rattr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
  int rfd = (int)ll_create(&rattr, sizeof(rattr), 0);
  if (rfd < 0) { perror("landlock-exec: create_ruleset"); return 4; }

  for (int a = 0; a < nallow; a++) {
    int pfd = open(allows[a], O_PATH | O_CLOEXEC);
    if (pfd < 0) continue; /* a missing floor entry is simply not granted */
    struct ll_path_beneath_attr pb;
    pb.allowed_access = LANDLOCK_ACCESS_FS_EXECUTE;
    pb.parent_fd = pfd;
    if (ll_add(rfd, LANDLOCK_RULE_PATH_BENEATH, &pb, 0) < 0)
      fprintf(stderr, "landlock-exec: add_rule(%s) failed: %s\n", allows[a], strerror(errno));
    close(pfd);
  }

  if (ll_restrict(rfd, 0)) { perror("landlock-exec: restrict_self"); return 5; }
  close(rfd);

  execve(cmd[0], cmd, environ);
  fprintf(stderr, "landlock-exec: execve(%s): %s\n", cmd[0], strerror(errno));
  return 127;
}
