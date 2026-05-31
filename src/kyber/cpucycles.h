#ifndef CPUCYCLES_H
#define CPUCYCLES_H
#include <stdint.h>
/* Portable stub: returns 0 on non-x86 platforms */
static inline uint64_t cpucycles(void) { return 0; }
#endif
