#ifndef TEST_STDLIB_H
#define TEST_STDLIB_H
#include <stdint.h>
extern uint32_t test_now;
typedef uint32_t absolute_time_t;
static inline absolute_time_t get_absolute_time(void) { return test_now; }
static inline uint32_t to_ms_since_boot(absolute_time_t t) { return t; }
#endif
