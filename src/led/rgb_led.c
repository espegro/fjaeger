#include "rgb_led.h"

#include "hardware/clocks.h"
#include "hardware/pio.h"
#include "pico/stdlib.h"

#include "state.h"
#include "rgb_led.pio.h"

#define FJ_LED_PIN 22u
#define FJ_LED_FREQ 800000.0f

static PIO led_pio = pio0;
static uint led_sm;
static bool usb_mounted;
static bool usb_suspended;
static uint32_t last_grb = 0xffffffffu;
static uint32_t activity_until_ms;

static void put_rgb(uint8_t red, uint8_t green, uint8_t blue) {
    /* WS2812 wire order is GRB, MSB first. Keep brightness deliberately low
     * for a status light in a small USB enclosure. */
    uint32_t grb = ((uint32_t)green << 16) |
                   ((uint32_t)red << 8) |
                   blue;
    if (grb == last_grb) return;
    pio_sm_put_blocking(led_pio, led_sm, grb << 8);
    last_grb = grb;
}

void fj_led_init(void) {
    uint offset = pio_add_program(led_pio, &fjaeger_ws2812_program);
    led_sm = pio_claim_unused_sm(led_pio, true);
    fjaeger_ws2812_program_init(led_pio, led_sm, offset, FJ_LED_PIN,
                                FJ_LED_FREQ);
    usb_mounted = false;
    usb_suspended = false;
    activity_until_ms = 0;
    put_rgb(0, 0, 0);
}

void fj_led_set_mounted(bool mounted) {
    usb_mounted = mounted;
}

void fj_led_set_suspended(bool suspended) {
    usb_suspended = suspended;
}

void fj_led_activity(void) {
    activity_until_ms = to_ms_since_boot(get_absolute_time()) + 100u;
}

void fj_led_task(void) {
    uint32_t now = to_ms_since_boot(get_absolute_time());

    if ((int32_t)(activity_until_ms - now) > 0) {
        put_rgb(0, 0, 28);       /* blue pulse: USB activity */
        return;
    }

    if (fj_state_get() == FJ_STATE_UNLOCKED) {
        put_rgb(0, 24, 0);       /* green: unlocked */
        return;
    }

    uint32_t interval = usb_suspended ? 1200u : 500u;
    bool phase = ((now / interval) & 1u) != 0;

    if (!phase) {
        put_rgb(0, 0, 0);
    } else if (usb_suspended) {
        put_rgb(0, 0, 20);       /* blue: USB suspended */
    } else if (!usb_mounted) {
        put_rgb(20, 8, 0);       /* amber: not enumerated */
    } else {
        put_rgb(24, 0, 0);       /* red blink: locked */
    }
}
