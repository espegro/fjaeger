/*
 * Fjaeger - security key firmware entry point.
 *
 * RP2350 USB dongle exposing:
 *   - CDC serial console  (lock / unlock / key management)
 *   - FIDO U2F + CTAP2 over HID (SSH / WebAuthn authentication)
 *   - encrypted MSC drive (AES-128-XTS, mounted only when unlocked)
 */
#include <stdio.h>

#include "pico/stdlib.h"
#include "pico/rand.h"
#include "hardware/watchdog.h"

#include "tusb.h"
#include "bsp/board_api.h"

#include "state.h"
#include "keys.h"
#include "restore_boot.h"
#include "crypto.h"
#include "msc_disk.h"
#include "cdc_console.h"
#include "u2f.h"
#include "ctap2.h"
#include "hmac_runtime.h"
#include "hmac_store.h"
#include "boot_button.h"
#include "rgb_led.h"

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */
int main(void) {
    board_init();
    stdio_init_all();

    /* Fail closed before accessing keys or exposing USB services. */
    if (!fj_crypto_ok()) panic("SHA-256 self-test failed");
    if (!fj_restore_boot_recover()) panic("Restore recovery required");

    /* Initialise the security-key subsystems. */
    fj_keys_init();
    if (!fj_keys_ready()) panic("Key store unavailable");
    fj_state_init();
    /* No physical OTP provider is enabled yet. An OTP-protected or damaged
     * store must never silently fall back to the development root. */
    if (!fj_hmac_runtime_init(NULL, fj_boot_button_pressed(),
                              to_ms_since_boot(get_absolute_time())))
        panic("HMAC store or configuration unavailable");
    fj_msc_init();
    fj_u2f_init();
    fj_ctap2_init();
    fj_ctap2_set_external_id_lookup(fj_hmac_store_id_exists, NULL);
    fj_console_init();
    fj_led_init();

    /* Start the USB device stack. */
    tud_init(BOARD_TUD_RHPORT);
    if (board_init_after_tusb) board_init_after_tusb();

    /* Seed the U2F counter from the hardware RNG. */
    (void)get_rand_64();

    uint32_t last_hmac_button_sample = to_ms_since_boot(get_absolute_time());
    while (1) {
        tud_task();
        fj_led_task();
        fj_state_tick();
        fj_console_task();
        fj_u2f_task();
        fj_ctap2_task();
        fj_msc_task();
        const fj_hmac_policy_t *policy = fj_hmac_runtime_policy();
        uint32_t now = to_ms_since_boot(get_absolute_time());
        if (policy && policy->mode == FJ_HMAC_ARMED && !policy->armed &&
            now - last_hmac_button_sample >= 10u) {
            last_hmac_button_sample = now;
            fj_hmac_runtime_poll(fj_boot_button_pressed(), now);
        }
    }
}

/* ------------------------------------------------------------------ */
/* TinyUSB device callbacks                                            */
/* ------------------------------------------------------------------ */
void tud_mount_cb(void)   { fj_led_set_mounted(true); }
void tud_umount_cb(void)  { fj_led_set_mounted(false); }
void tud_suspend_cb(bool r) {
    (void)r;
    fj_led_set_suspended(true);
}
void tud_resume_cb(void) {
    fj_led_set_suspended(false);
    fj_led_set_mounted(tud_mounted());
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

    fj_led_activity();
    fj_u2f_hid_rx(buffer, bufsize);
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
