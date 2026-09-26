#ifndef FJAEGER_RGB_LED_H
#define FJAEGER_RGB_LED_H

#include <stdbool.h>

/* GPIO22 WS2812/SK6812 status LED. */
void fj_led_init(void);
void fj_led_task(void);
void fj_led_set_mounted(bool mounted);
void fj_led_set_suspended(bool suspended);

#endif
