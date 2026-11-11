#ifndef TEST_TUSB_H
#define TEST_TUSB_H
#include <stdbool.h>
#include <stdint.h>
bool tud_mounted(void);
bool tud_hid_ready(void);
bool tud_hid_n_report(uint8_t instance, uint8_t id, const void *data, uint16_t len);
#endif
