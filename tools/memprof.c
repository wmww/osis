// LD_PRELOAD heap recorder for tools/memprof: every malloc-family allocation's size and call
// stack while it is live; at exit writes the live ones, one line per distinct stack
// (`bytes count object:offset...`), to $MEMPROF_OUT.<pid>, with a `# live` total first. Bookkeeping
// lives in mmap'd tables (never the heap it records), under one lock.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define DEPTH 40
#define LIVE_BITS 24 // live allocations tracked at once
#define STACK_BITS 20 // distinct stacks
struct live { uintptr_t p; size_t size; uint32_t stack; };
struct stack { uint64_t hash; int depth; void *f[DEPTH]; };
static struct live *lives;
static struct stack *stacks;
static uint32_t nstacks;
static size_t live_bytes, dropped, used; // used: slots holding a live entry or a tombstone
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static __thread int inside;
static int on;

static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);
static void (*real_free)(void *);
static int (*real_memalign)(void **, size_t, size_t);
static void *(*real_aligned)(size_t, size_t);

// dlsym may calloc before real_calloc is known: a small static arena serves it
static char early[1 << 16];
static size_t early_used;
static int is_early(void *p) { return (char *)p >= early && (char *)p < early + sizeof early; }

static uint64_t mix(uint64_t h) {
    h ^= h >> 33; h *= 0xff51afd7ed558ccdULL; h ^= h >> 33; h *= 0xc4ceb9fe1a85ec53ULL;
    return h ^ (h >> 33);
}

static uint32_t stack_id(void **f, int depth) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < depth; i++) h = mix(h ^ (uint64_t)f[i]);
    uint32_t mask = (1u << STACK_BITS) - 1;
    for (uint32_t i = h & mask;; i = (i + 1) & mask) {
        struct stack *s = &stacks[i];
        if (s->depth == 0) {
            if (nstacks >= mask / 2) return UINT32_MAX;
            s->hash = h; s->depth = depth; memcpy(s->f, f, sizeof(void *) * depth);
            nstacks++;
            return i;
        }
        if (s->hash == h && s->depth == depth && !memcmp(s->f, f, sizeof(void *) * depth)) return i;
    }
}

// Every live entry into a fresh table once half the slots are used, dropping the tombstones.
static void rebuild(void) {
    uint64_t mask = (1ull << LIVE_BITS) - 1;
    struct live *old = lives;
    lives = mmap(NULL, sizeof(struct live) << LIVE_BITS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    used = 0;
    for (uint64_t j = 0; j <= mask; j++) {
        if (old[j].p <= 1) continue;
        uint64_t i = mix(old[j].p) & mask;
        while (lives[i].p) i = (i + 1) & mask;
        lives[i] = old[j];
        used++;
    }
    munmap(old, sizeof(struct live) << LIVE_BITS);
}

static void note(void *p, size_t size) {
    if (!on || !p || inside) return;
    inside = 1;
    void *f[DEPTH + 2];
    int d = backtrace(f, DEPTH + 2);
    pthread_mutex_lock(&lock);
    // frames 0-1: note and the interposed function
    uint32_t s = d > 2 ? stack_id(f + 2, d - 2) : UINT32_MAX;
    uint64_t mask = (1ull << LIVE_BITS) - 1;
    if (used > mask / 2) rebuild();
    uint64_t i = mix((uintptr_t)p) & mask;
    while (lives[i].p > 1) i = (i + 1) & mask;
    if (s == UINT32_MAX) dropped++;
    else {
        if (!lives[i].p) used++;
        lives[i] = (struct live){(uintptr_t)p, size, s};
        live_bytes += size;
    }
    pthread_mutex_unlock(&lock);
    inside = 0;
}

static void forget(void *p) {
    if (!on || !p) return;
    pthread_mutex_lock(&lock);
    uint64_t mask = (1ull << LIVE_BITS) - 1;
    for (uint64_t i = mix((uintptr_t)p) & mask; lives[i].p; i = (i + 1) & mask) {
        if (lives[i].p == (uintptr_t)p) {
            live_bytes -= lives[i].size;
            lives[i].p = 1; // a tombstone: probes go on past it
            break;
        }
    }
    pthread_mutex_unlock(&lock);
}

static void resolve(void) {
    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");
    real_realloc = dlsym(RTLD_NEXT, "realloc");
    real_free = dlsym(RTLD_NEXT, "free");
    real_memalign = dlsym(RTLD_NEXT, "posix_memalign");
    real_aligned = dlsym(RTLD_NEXT, "aligned_alloc");
}

void *malloc(size_t n) {
    if (!real_malloc) resolve();
    void *p = real_malloc(n);
    note(p, n);
    return p;
}
void *calloc(size_t a, size_t b) {
    if (!real_calloc) {
        size_t n = (a * b + 15) & ~(size_t)15;
        if (early_used + n > sizeof early) return NULL;
        void *p = early + early_used;
        early_used += n;
        return p;
    }
    void *p = real_calloc(a, b);
    note(p, a * b);
    return p;
}
void *realloc(void *old, size_t n) {
    if (!real_realloc) resolve();
    if (is_early(old)) {
        void *p = malloc(n);
        if (p) memcpy(p, old, n);
        return p;
    }
    forget(old);
    void *p = real_realloc(old, n);
    note(p, n);
    return p;
}
void free(void *p) {
    if (!p || is_early(p)) return;
    if (!real_free) resolve();
    forget(p);
    real_free(p);
}
int posix_memalign(void **out, size_t align, size_t n) {
    if (!real_memalign) resolve();
    int r = real_memalign(out, align, n);
    if (r == 0) note(*out, n);
    return r;
}
void *aligned_alloc(size_t align, size_t n) {
    if (!real_aligned) resolve();
    void *p = real_aligned(align, n);
    note(p, n);
    return p;
}

static void dump(void) {
    const char *out = getenv("MEMPROF_OUT");
    if (!on || !out) return;
    inside = 1;
    pthread_mutex_lock(&lock);
    on = 0;
    uint64_t *bytes = mmap(NULL, sizeof(uint64_t) * 2 << STACK_BITS, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    for (uint64_t i = 0; i < 1ull << LIVE_BITS; i++) {
        if (lives[i].p > 1) {
            bytes[2 * lives[i].stack] += lives[i].size;
            bytes[2 * lives[i].stack + 1]++;
        }
    }
    char fn[4096], abs[PATH_MAX];
    snprintf(fn, sizeof fn, "%s.%d", out, getpid());
    FILE *f = fopen(fn, "w");
    if (f) {
        fprintf(f, "# live %zu dropped %zu\n", live_bytes, dropped);
        Dl_info info;
        const char *last = NULL;
        for (uint32_t s = 0; s < 1u << STACK_BITS; s++) {
            if (!bytes[2 * s]) continue;
            fprintf(f, "%lu %lu", (unsigned long)bytes[2 * s], (unsigned long)bytes[2 * s + 1]);
            for (int j = 0; j < stacks[s].depth; j++) {
                void *a = stacks[s].f[j];
                if (dladdr(a, &info) && info.dli_fname) {
                    if (info.dli_fname != last) {
                        last = info.dli_fname;
                        if (!realpath(last, abs)) snprintf(abs, sizeof abs, "%s", last);
                    }
                    fprintf(f, " %s:%lx", abs, (unsigned long)((char *)a - (char *)info.dli_fbase) - 1);
                }
            }
            fputc('\n', f);
        }
        fclose(f);
    }
    pthread_mutex_unlock(&lock);
}

__attribute__((constructor)) static void init(void) {
    resolve();
    if (!getenv("MEMPROF_OUT")) return;
    void *warm[2];
    backtrace(warm, 2); // loads the unwinder before anything is recorded
    int fl = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    lives = mmap(NULL, sizeof(struct live) << LIVE_BITS, PROT_READ | PROT_WRITE, fl, -1, 0);
    stacks = mmap(NULL, sizeof(struct stack) << STACK_BITS, PROT_READ | PROT_WRITE, fl, -1, 0);
    if (lives == MAP_FAILED || stacks == MAP_FAILED) return;
    on = 1;
    atexit(dump);
}
