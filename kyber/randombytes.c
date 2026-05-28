#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
void randombytes(uint8_t *out, size_t outlen) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open /dev/urandom"); exit(EXIT_FAILURE); }
    size_t n = 0;
    while (n < outlen) {
        ssize_t r = read(fd, out + n, outlen - n);
        if (r <= 0) { perror("read /dev/urandom"); exit(EXIT_FAILURE); }
        n += r;
    }
    close(fd);
}
