// LD_PRELOAD sampler for tools/cpuprof: a SIGPROF every 2 ms of process CPU (or, with
// CPUPROF_INSTR=N, every N user-space instructions of each thread: immune to the box's load)
// records the backtrace of the thread it lands on; at exit writes each sample as a line of
// `object:offset` frames to $CPUPROF_OUT.<pid> (one file per process: a wrapper exec'd under
// the preload writes its own, or none if it took no samples).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <execinfo.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#define MAXS 120000
#define DEPTH 160
static void *buf[MAXS][DEPTH];
static int depth[MAXS];
static atomic_int n;
static volatile int stop;

static void handler(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)si; (void)uc;
    if (stop) return;
    int i = atomic_fetch_add(&n, 1);
    if (i < MAXS) depth[i] = backtrace(buf[i], DEPTH);
}

static void dump(void) {
    stop = 1;
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
    // objects by absolute path: the main binary's dli_fname is as it was run (often relative), and
    // the report may run from another directory. One cached name: frames mostly share an object.
    const char *last = NULL;
    char abs[PATH_MAX];
    for (int i = 0; i < m; i++) {
        // frames 0-1 are the handler and the signal trampoline
        for (int j = 2; j < depth[i]; j++) {
            void *a = buf[i][j];
            if (dladdr(a, &info) && info.dli_fname) {
                if (info.dli_fname != last) {
                    last = info.dli_fname;
                    if (!realpath(last, abs)) snprintf(abs, sizeof abs, "%s", last);
                }
                fprintf(f, "%s:%lx ", abs, (unsigned long)((char *)a - (char *)info.dli_fbase) - 1);
            }
        }
        fputc('\n', f);
    }
    fclose(f);
}

// CPUPROF_INSTR: a sampling instruction counter per thread, its overflow signalled to that thread
static long every(void) {
    const char *p = getenv("CPUPROF_INSTR");
    return p ? atol(p) : 0;
}
static void arm(void) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_INSTRUCTIONS;
    a.sample_period = every();
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.wakeup_events = 1;
    int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) return;
    fcntl(fd, F_SETFL, O_ASYNC);
    fcntl(fd, F_SETSIG, SIGPROF);
    struct f_owner_ex o = {F_OWNER_TID, (pid_t)syscall(SYS_gettid)};
    fcntl(fd, F_SETOWN_EX, &o);
}
struct start {
    void *(*f)(void *);
    void *arg;
};
static void *trampoline(void *p) {
    struct start s = *(struct start *)p;
    free(p);
    arm();
    return s.f(s.arg);
}
int pthread_create(pthread_t *t, const pthread_attr_t *at, void *(*f)(void *), void *arg) {
    static int (*real)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
    if (!real) real = dlsym(RTLD_NEXT, "pthread_create");
    if (!getenv("CPUPROF_OUT") || every() <= 0) return real(t, at, f, arg);
    struct start *s = malloc(sizeof *s);
    s->f = f;
    s->arg = arg;
    return real(t, at, trampoline, s);
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
    if (every() > 0) {
        arm();
    } else {
        struct itimerval it = {{0, 2000}, {0, 2000}};
        setitimer(ITIMER_PROF, &it, NULL);
    }
    atexit(dump);
}
