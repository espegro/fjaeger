/*
 * Fjaeger - security key firmware entry point.
 *
 * RP2350 USB dongle exposing:
 *   - CDC serial console  (lock / unlock / key management)
 *   - FIDO U2F + CTAP2 over HID (SSH / WebAuthn authentication)
 *   - encrypted MSC drive (AES-256-XTS, mounted only when unlocked)
 */
#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/watchdog.h"

#include "tusb.h"
#include "bsp/board_api.h"

#include "state.h"
#include "keys.h"
#include "crypto.h"
#include "msc_disk.h"
#include "cdc_console.h"
#include "u2f.h"
#include "ctap2.h"

/* ------------------------------------------------------------------ */
/* LED blink pattern                                                   */
/* ------------------------------------------------------------------ */
enum {
    BLINK_NOT_MOUNTED = 250,
    BLINK_MOUNTED = 1000,
    BLINK_SUSPENDED = 2500,
};
static uint32_t blink_interval_ms = BLINK_NOT_MOUNTED;

static void led_blinking_task(void) {
    static uint32_t start_ms = 0;
    static bool led_state = false;

    if (board_millis() - start_ms < blink_interval_ms) return;
    start_ms += blink_interval_ms;

    /* Solid when unlocked, blinking when locked. */
    if (fj_state_get() == FJ_STATE_UNLOCKED) {
        board_led_write(true);
    } else {
        board_led_write(led_state);
        led_state = !led_state;
    }
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    board_init();
    stdio_init_all();

    /* Initialise the security-key subsystems. */
    fj_keys_init();
    fj_state_init();
    fj_crypto_ok();          /* verify mbedTLS initialised */
    fj_msc_init();
    fj_u2f_init();
    fj_ctap2_init();
    fj_console_init();

    /* Start the USB device stack. */
    tud_init(BOARD_TUD_RHPORT);
    if (board_init_after_tusb) board_init_after_tusb();

    /* Seed the U2F counter from the hardware RNG. */
    (void)get_rand_64();

    while (1) {
        tud_task();
        led_blinking_task();
        fj_state_tick();
        fj_console_task();
        fj_u2f_task();
        fj_ctap2_task();
    }
}

/* ------------------------------------------------------------------ */
/* TinyUSB device callbacks                                            */
/* ------------------------------------------------------------------ */
void tud_mount_cb(void)   { blink_interval_ms = BLINK_MOUNTED; }
void tud_umount_cb(void)  { blink_interval_ms = BLINK_NOT_MOUNTED; }
void tud_suspend_cb(bool r) {
    (void)r;
    blink_interval_ms = BLINK_SUSPENDED;
}
void tud_resume_cb(void) {
    blink_interval_ms = tud_mounted() ? BLINK_MOUNTED : BLINK_NOT_MOUNTED;
}

/* ------------------------------------------------------------------ */
/* HID callbacks (FIDO U2F)                                            */
/* ------------------------------------------------------------------ */

/* Host -> device: an OUT report (U2F command frame). */
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize) {
    (void)instance;
    (void)report_id;
    (void)report_type;

    fj_u2f_hid_rx(buffer, bufsize);

    /* Immediately push any pending outbound reports. */
    uint8_t out[64];
    while (fj_u2f_ready() && fj_u2f_pop_report(out)) {
        if (!tud_hid_n_report(instance, 0, out, 64)) break;
    }
}

/* Device -> host: report request (unused for raw U2F). */
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type, uint8_t *buffer,
                               uint16_t reqlen) {
    (void)instance; (void)report_id; (void)report_type;
    (void)buffer;   (void)reqlen;
    return 0;
}

/* Report descriptor for the HID (U2F) interface. */
extern const uint8_t desc_hid_report[];
uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    (void)instance;
    return desc_hid_report;
}

/* CDC callback: line state changed. */
void tud_cdc_line_state_cb(uint8_t itf, bool dtr, bool rts) {
    (void)itf; (void)rts; (void)dtr;
}