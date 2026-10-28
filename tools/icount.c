// icount CMD...: runs CMD, prints the user-space instructions it and its threads and children
// retired to stderr ("INSTR <n>"), exits with CMD's status. Needs perf_event_paranoid <= 2.
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: icount CMD...\n");
        return 2;
    }
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = PERF_TYPE_HARDWARE;
    a.size = sizeof a;
    a.config = PERF_COUNT_HW_INSTRUCTIONS;
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.inherit = 1;
    a.enable_on_exec = 1;
    int go[2];
    if (pipe(go) != 0) {
        perror("pipe");
        return 2;
    }
    pid_t p = fork();
    if (p < 0) {
        perror("fork");
        return 2;
    }
    if (p == 0) {
        // wait until the counter is attached, then exec (which enables it)
        char c;
        close(go[1]);
        if (read(go[0], &c, 1) != 1) _exit(127);
        execvp(argv[1], argv + 1);
        perror("execvp");
        _exit(127);
    }
    int fd = (int)syscall(SYS_perf_event_open, &a, p, -1, -1, 0);
    if (fd < 0) perror("perf_event_open");
    close(go[0]);
    if (write(go[1], "x", 1) != 1) perror("write");
    close(go[1]);
    int st;
    waitpid(p, &st, 0);
    uint64_t n = 0;
    if (fd >= 0 && read(fd, &n, sizeof n) == sizeof n)
        fprintf(stderr, "INSTR %llu\n", (unsigned long long)n);
    else
        fprintf(stderr, "INSTR unavailable\n");
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}
