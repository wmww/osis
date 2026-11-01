// LD_PRELOAD sampler for tools/cpuprof: a SIGPROF every 2 ms of process CPU records the
// backtrace of the thread it lands on; at exit writes each sample as a line of
// `object:offset` frames to $CPUPROF_OUT.<pid> (one file per process: a wrapper exec'd under
// the preload writes its own, or none if it took no samples).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define MAXS 400000
#define DEPTH 48
static void *buf[MAXS][DEPTH];
static int depth[MAXS];
static atomic_int n;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)si; (void)uc;
    int i = atomic_fetch_add(&n, 1);
    if (i < MAXS) depth[i] = backtrace(buf[i], DEPTH);
}

static void dump(void) {
    struct itimerval off = {0};
    setitimer(ITIMER_PROF, &off, NULL);
    const char *out = getenv("CPUPROF_OUT");
    int m = atomic_load(&n);
    if (!out || m == 0) return;
    if (m > MAXS) m = MAXS;
    char fn[4096];
    snprintf(fn, sizeof fn, "%s.%d", out, getpid());
    FILE *f = fopen(fn, "w");
    if (!f) return;
    Dl_info info;
    for (int i = 0; i < m; i++) {
        // frames 0-1 are the handler and the signal trampoline
        for (int j = 2; j < depth[i]; j++) {
            void *a = buf[i][j];
            if (dladdr(a, &info) && info.dli_fname)
                fprintf(f, "%s:%lx ", info.dli_fname, (unsigned long)((char *)a - (char *)info.dli_fbase) - 1);
        }
        fputc('\n', f);
    }
    fclose(f);
}

__attribute__((constructor)) static void init(void) {
    if (!getenv("CPUPROF_OUT")) return;
    void *warm[2];
    backtrace(warm, 2); // loads the unwinder outside the handler
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGPROF, &sa, NULL);
    struct itimerval it = {{0, 2000}, {0, 2000}};
    setitimer(ITIMER_PROF, &it, NULL);
    atexit(dump);
}
