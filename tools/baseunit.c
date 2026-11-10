// baseunit: the box's time-limit base unit (notes/build.md, Time limits). Runs 16 fixed work
// quanta on one thread per core (sysconf), so every hardware thread is busy as in a build or a
// test run, and prints "WALL <s> CPU <s>": the wall of the 16 quanta and their CPU-s. A quantum mixes
// what builds and tests do: integer hashing, random reads and writes over a buffer past the
// caches, allocation, and sorting. Deterministic: same work on every box and run.
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#define QUANTA 16
#define BUF (4u << 20) // u64 words: 32 MB per quantum
#define ROUNDS 3

static int next_q;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static volatile uint64_t sink;

static uint64_t mix(uint64_t x) {
    x ^= x >> 31; x *= 0x7fb5d329728ea185ull; x ^= x >> 27; x *= 0x81dadef4bc2dd44dull; x ^= x >> 33;
    return x;
}

static int cmp(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static void quantum(uint64_t seed) {
    uint64_t *buf = malloc(BUF * sizeof *buf), acc = seed;
    for (uint32_t i = 0; i < BUF; i++) buf[i] = mix(seed + i);
    for (int r = 0; r < ROUNDS; r++) {
        for (uint32_t i = 0; i < BUF; i++) { // dependent random access: memory latency
            uint64_t j = acc % BUF;
            acc = mix(acc ^ buf[j]);
            buf[j] = acc;
        }
        for (uint32_t c = 0; c < 64; c++) { // many small allocations and sorts
            uint32_t n = 4096 + (uint32_t)(mix(acc + c) % 4096);
            uint64_t *v = malloc(n * sizeof *v);
            for (uint32_t i = 0; i < n; i++) v[i] = buf[(acc + i * 7919u) % BUF];
            qsort(v, n, sizeof *v, cmp);
            acc ^= v[n / 2];
            free(v);
        }
    }
    sink += acc;
    free(buf);
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&mu);
        int q = next_q++;
        pthread_mutex_unlock(&mu);
        if (q >= QUANTA) return NULL;
        quantum((uint64_t)q * 0x9e3779b97f4a7c15ull);
    }
}

int main(void) {
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) n = 1;
    pthread_t *t = malloc(n * sizeof *t);
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (long i = 0; i < n; i++) pthread_create(&t[i], NULL, worker, NULL);
    for (long i = 0; i < n; i++) pthread_join(t[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &b);
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    double cpu = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 + ru.ru_stime.tv_sec + ru.ru_stime.tv_usec / 1e6;
    printf("WALL %.2f CPU %.2f THREADS %ld\n", (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9, cpu, n);
    return 0;
}
