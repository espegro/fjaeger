#ifndef TEST_PICO_TIME_H
#define TEST_PICO_TIME_H

#include <stdint.h>

typedef int64_t absolute_time_t;

absolute_time_t get_absolute_time(void);
int64_t absolute_time_diff_us(absolute_time_t from, absolute_time_t to);

#endif
