/*
 * Fjaeger - serial console (USB CDC).
 *
 * Command interface:
 *   HELP
 *   STATUS
 *   LOCK
 *   UNLOCK <pin>
 *   SETPIN <pin>
 *   PROFILE LIST
 *   PROFILE CREATE <id> <name>
 *   PROFILE SELECT <id>
 *   PROFILE RENAME <id> <name>
 *   PROFILE ERASE <id>
 *   TIMEOUT <seconds>
 *   RESET
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "tusb.h"
#include "pico/time.h"
#include "pico/bootrom.h"
#include "hardware/watchdog.h"

#include "state.h"
#include "keys.h"
#include "ctap2.h"
#include "msc_disk.h"
#include "rgb_led.h"

#define LINE_MAX 96

#define PROMPT "fjaeger> "

static char line[LINE_MAX];
static size_t line_len = 0;
static bool was_connected = false;
static bool last_was_cr = false;

/* ------------------------------------------------------------------ */
/* Line output (respects CDC back-pressure)                            */
/* ------------------------------------------------------------------ */
static void out(const char *s) {
    while (*s) {
        if (!tud_cdc_write_available()) {
            tud_cdc_write_flush();
            tud_task();
            tight_loop_contents();
            continue;
        }
        tud_cdc_write_char(*s++);
    }
    tud_cdc_write_flush();
}

static void outln(const char *s) {
    out(s);
    out("\r\n");
}

/* Prevent the compiler from retaining command arguments (including PINs and
 * PUKs) in the reusable input buffer. The firmware never echoes input; users
 * must also keep local echo disabled in their terminal program. */
static void clear_line(void) {
    volatile char *p = line;
    for (size_t i = 0; i < sizeof(line); i++) p[i] = 0;
}

/* ------------------------------------------------------------------ */
/* Token helpers                                                       */
/* ------------------------------------------------------------------ */
static char *next_token(char **cursor) {
    char *p = *cursor;
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) { *cursor = p; return NULL; }
    char *start = p;
    while (*p && !isspace((unsigned char)*p)) p++;
    if (*p) *p++ = '\0';
    *cursor = p;
    return start;
}

static bool parse_uint(const char *s, unsigned long *value) {
    char *end = NULL;
    if (!s || !*s) return false;
    unsigned long parsed = strtoul(s, &end, 10);
    if (end == s || *end != '\0') return false;
    *value = parsed;
    return true;
}

/* ------------------------------------------------------------------ */
/* Command handlers                                                    */
/* ------------------------------------------------------------------ */
static void cmd_help(void) {
    outln("Fjaeger commands (case-insensitive):");
    outln("  HELP|?                     this help");
    outln("  STATUS                     show device & disk state, slot, timeout");
    outln("  LOCK                       lock device (and close the disk)");
    outln("  UNLOCK <pin>               unlock device for key ops only");
    outln("  SETPIN <pin>               set/change PIN");
    outln("  UNLOCKPUK <puk>            unblock device with recovery PUK");
    outln("  PUK <code>                 set/change the recovery PUK");
    outln("  DISK STATUS                show drive lock state");
    outln("  DISK SETPIN <pin>          set/change the disk PIN");
    outln("  DISK UNLOCK <pin>          unlock/mount the drive with disk PIN");
    outln("  DISK UNBLOCK <puk>         clear disk-PIN block (PIN still required)");
    outln("  DISK LOCK                  lock/unmount the drive");
    outln("  TIMEOUT <sec>              save auto-lock delay (default 900; 0 = off)");
    outln("  RESET                      reboot the device");
    outln("  PROFILE LIST               list all profiles, active flag & credential count");
    outln("  PROFILE CREATE <id> <name> create a new empty profile (0-7)");
    outln("  PROFILE SELECT <id>        set & save the active profile");
    outln("  PROFILE RENAME <id> <name> rename a profile");
    outln("  PROFILE ERASE <id>         erase a profile and its credentials");
}

static void cmd_status(void) {
    char buf[192];
    fj_security_t sec = {0};
    bool have_sec = fj_keys_get_security(&sec);
    snprintf(buf, sizeof(buf), "state: %s\r\n"
             "disk: %s\r\n"
             "pin_blocked: %s\r\n"
             "pin_fail: %u\r\n"
             "disk_blocked: %s\r\n"
             "disk_fail: %u\r\n"
             "puk: %s\r\n"
             "puk_fail: %u\r\n"
             "active_profile: %u\r\n"
             "profiles: %u\r\n"
             "timeout: %lus",
             fj_state_get() == FJ_STATE_UNLOCKED ? "unlocked" : "locked",
             fj_msc_is_ready() ? "unlocked" : "locked",
             (have_sec && sec.pin_blocked) ? "yes" : "no", (unsigned)sec.pin_fail,
             (have_sec && sec.disk_blocked) ? "yes" : "no", (unsigned)sec.disk_fail,
             fj_keys_puk_configured() ? "set" : "unset", (unsigned)sec.puk_fail,
             fj_keys_active_profile(), fj_keys_profile_count(),
             (unsigned long)fj_state_timeout());
    outln(buf);
}

static void cmd_lock(void) {
    fj_state_lock();
    outln("OK locked");
}

static void cmd_unlock(const char *pin) {
    if (!pin) {
        outln("ERR usage: UNLOCK <pin>");
        return;
    }
    if (fj_state_pin_blocked()) {
        outln("ERR PIN blocked, use UNLOCKPUK <puk>");
        return;
    }
    if (fj_state_unlock(pin)) {
        /* Only unlocks the device for key operations. The encrypted drive
         * is a separate step: DISK UNLOCK. */
        outln("OK unlocked");
    } else {
        fj_security_t sec = {0};
        fj_keys_get_security(&sec);
        if (sec.pin_blocked) {
            char buf[64];
            snprintf(buf, sizeof(buf),
                     "ERR PIN blocked after %u fails, use UNLOCKPUK <puk>",
                     (unsigned)FJ_MAX_PIN_FAILS);
            outln(buf);
        } else {
            char buf[64];
            snprintf(buf, sizeof(buf),
                     "ERR bad pin (%u/%u left)", (unsigned)FJ_MAX_PIN_FAILS - sec.pin_fail,
                     (unsigned)FJ_MAX_PIN_FAILS);
            outln(buf);
        }
    }
}

static void cmd_unlock_puk(const char *puk) {
    if (!puk) {
        outln("ERR usage: UNLOCKPUK <puk>");
        return;
    }
    switch (fj_state_unlock_puk(puk)) {
        case FJ_PUK_OK:    outln("OK unlocked via PUK"); break;
        case FJ_PUK_WRONG: outln("ERR wrong PUK"); break;
        case FJ_PUK_UNSET: outln("ERR no PUK configured"); break;
        case FJ_PUK_WIPED: outln("OK too many wrong PUKs, device wiped"); break;
    }
}

static bool require_unlocked(void);

static void cmd_set_puk(const char *puk) {
    if (!puk) {
        outln("ERR usage: PUK <code>");
        return;
    }
    if (!require_unlocked()) return;
    if (fj_state_set_puk(puk)) outln("OK recovery PUK set");
    else outln("ERR invalid PUK (8-64 chars) or device locked");
}

/* DISK UNLOCK <pin> / SETPIN <pin> / LOCK / STATUS — independent drive lock. */
static void cmd_disk(const char *sub, char *rest) {
    if (!sub) {
        outln("ERR DISK requires subcommand (UNLOCK|UNBLOCK|LOCK|SETPIN|STATUS)");
        return;
    }
    if (strcasecmp(sub, "status") == 0) {
        char buf[96];
        fj_security_t sec = {0};
        fj_keys_get_security(&sec);
        snprintf(buf, sizeof(buf), "disk: %s%s\r\n"
                 "disk_fail: %u",
                 fj_msc_is_ready() ? "unlocked" : "locked",
                 sec.disk_blocked ? " (PIN blocked, use DISK UNBLOCK)" : "",
                 (unsigned)sec.disk_fail);
        outln(buf);
    } else if (strcasecmp(sub, "unlock") == 0) {
        if (!require_unlocked()) return;
        const char *pin = next_token(&rest);
        if (!pin) { outln("ERR usage: DISK UNLOCK <pin>"); return; }
        if (fj_msc_pin_blocked()) {
            outln("ERR disk PIN blocked, use DISK UNBLOCK <puk>");
            return;
        }
        if (fj_msc_unlock(pin)) outln("OK disk unlocked");
        else {
            fj_security_t sec = {0};
            fj_keys_get_security(&sec);
            if (sec.disk_blocked) {
                outln("ERR disk PIN blocked, use DISK UNBLOCK <puk>");
            } else {
                char buf[64];
                snprintf(buf, sizeof(buf),
                         "ERR bad disk pin (%u/%u left)",
                         (unsigned)(FJ_MAX_PIN_FAILS - sec.disk_fail),
                         (unsigned)FJ_MAX_PIN_FAILS);
                outln(buf);
            }
        }
    } else if (strcasecmp(sub, "unblock") == 0) {
        if (!require_unlocked()) return;
        const char *puk = next_token(&rest);
        if (!puk) { outln("ERR usage: DISK UNBLOCK <puk>"); return; }
        switch (fj_msc_unblock_puk(puk)) {
            case FJ_PUK_OK:    outln("OK disk PIN unblocked; use DISK UNLOCK <pin>"); break;
            case FJ_PUK_WRONG: outln("ERR wrong PUK"); break;
            case FJ_PUK_UNSET: outln("ERR no PUK configured"); break;
            case FJ_PUK_WIPED: outln("OK too many wrong PUKs, device wiped"); break;
        }
    } else if (strcasecmp(sub, "lock") == 0) {
        fj_msc_lock();
        outln("OK disk locked");
    } else if (strcasecmp(sub, "setpin") == 0) {
        if (!require_unlocked()) return;
        const char *pin = next_token(&rest);
        if (!pin) { outln("ERR usage: DISK SETPIN <pin>"); return; }
        if (fj_msc_set_pin(pin)) outln("OK disk pin set");
        else outln("ERR disk pin invalid or drive locked");
    } else {
        outln("ERR unknown DISK subcommand (UNLOCK|UNBLOCK|LOCK|SETPIN|STATUS)");
    }
}

static void cmd_setpin(const char *pin) {
    if (!pin) {
        outln("ERR usage: SETPIN <pin>");
        return;
    }
    if (fj_state_set_pin(pin)) {
        outln("OK pin set");
    } else {
        outln("ERR invalid pin or device locked");
    }
}

static bool require_unlocked(void) {
    if (fj_state_get() == FJ_STATE_UNLOCKED) return true;
    outln("ERR device locked");
    return false;
}

static void cmd_profile_list(void) {
    char buf[96];
    fj_ctap2_cred_t creds[FJ_CTAP2_CREDS];
    fj_keys_ctap2_load(creds);
    for (unsigned i = 0; i < FJ_NUM_PROFILES; i++) {
        const fj_profile_t *p = fj_keys_profile_get(i);
        if (!p) continue;
        unsigned n = 0;
        for (unsigned j = 0; j < FJ_CTAP2_CREDS; j++) {
            if (creds[j].in_use && creds[j].profile_id == i) n++;
        }
        snprintf(buf, sizeof(buf), "profile %u: %s [%u]%s",
                 i, p->name, n,
                 i == fj_keys_active_profile() ? " (active)" : "");
        outln(buf);
    }
}

static void cmd_profile_select(const char *arg) {
    if (!require_unlocked()) return;
    if (!arg) {
        outln("ERR usage: PROFILE SELECT <id>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_PROFILES) {
        outln("ERR invalid profile id");
        return;
    }
    unsigned n = (unsigned)parsed;
    if (fj_keys_profile_select(n)) {
        /* A new active profile invalidates any buffered discovery so the
         * next assertion cannot reuse a credential from the old profile. */
        fj_ctap2_invalidate_discovery();
        char buf[64];
        snprintf(buf, sizeof(buf), "OK active profile = %u", n);
        outln(buf);
    } else {
        outln("ERR profile does not exist or out of range");
    }
}

static void cmd_profile_create(const char *arg, const char *name) {
    if (!require_unlocked()) return;
    if (!arg || !name) {
        outln("ERR usage: PROFILE CREATE <id> <name>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_PROFILES) {
        outln("ERR invalid profile id");
        return;
    }
    unsigned n = (unsigned)parsed;
    if (fj_keys_profile_create(n, name)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OK created profile %u", n);
        outln(buf);
    } else {
        outln("ERR profile already exists, empty name, or out of range");
    }
}

static void cmd_profile_rename(const char *arg, const char *name) {
    if (!require_unlocked()) return;
    if (!arg || !name) {
        outln("ERR usage: PROFILE RENAME <id> <name>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_PROFILES) {
        outln("ERR invalid profile id");
        return;
    }
    unsigned n = (unsigned)parsed;
    if (fj_keys_profile_rename(n, name)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OK renamed profile %u", n);
        outln(buf);
    } else {
        outln("ERR profile does not exist or empty name");
    }
}

static void cmd_profile_erase(const char *arg) {
    if (!require_unlocked()) return;
    if (!arg) {
        outln("ERR usage: PROFILE ERASE <id>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_PROFILES) {
        outln("ERR invalid profile id");
        return;
    }
    unsigned n = (unsigned)parsed;
    if (fj_state_profile_erase(n)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OK erased profile %u", n);
        outln(buf);
    } else {
        outln("ERR cannot erase active profile or profile does not exist");
    }
}

static void cmd_timeout(const char *arg) {
    if (!require_unlocked()) return;
    if (!arg) {
        outln("ERR usage: TIMEOUT <seconds>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed > UINT32_MAX) {
        outln("ERR invalid timeout");
        return;
    }
    uint32_t sec = (uint32_t)parsed;
    if (!fj_state_set_timeout(sec)) {
        outln("ERR timeout could not be saved");
        return;
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "OK timeout = %lus", (unsigned long)sec);
    outln(buf);
}

static void cmd_reset(const char *arg) {
    /* RESET BOOTSEL reboots into the ROM USB bootloader for re-flashing. */
    if (arg && strcasecmp(arg, "bootsel") == 0) {
        outln("OK resetting device to bootsel");
        fflush(NULL);
        tight_loop_contents();
        rom_reset_usb_boot(0, 0);
        while (1) tight_loop_contents();
    }
    outln("OK resetting device");
    fflush(NULL);
    tight_loop_contents();
    /* Software reset via watchdog. */
    watchdog_enable(1, 0);
    while (1) tight_loop_contents();
}

/* ------------------------------------------------------------------ */
/* Command dispatch                                                    */
/* ------------------------------------------------------------------ */
static void dispatch(char *cmdline) {
    fj_led_activity();
    char *p = cmdline;
    char *tok = next_token(&p);
    if (!tok) return;

    if (strcasecmp(tok, "help") == 0 || strcmp(tok, "?") == 0) {
        cmd_help();
    } else if (strcasecmp(tok, "status") == 0) {
        cmd_status();
    } else if (strcasecmp(tok, "lock") == 0) {
        cmd_lock();
    } else if (strcasecmp(tok, "unlock") == 0) {
        cmd_unlock(next_token(&p));
    } else if (strcasecmp(tok, "unlockpuk") == 0) {
        cmd_unlock_puk(next_token(&p));
    } else if (strcasecmp(tok, "puk") == 0) {
        cmd_set_puk(next_token(&p));
    } else if (strcasecmp(tok, "setpin") == 0) {
        cmd_setpin(next_token(&p));
    } else if (strcasecmp(tok, "disk") == 0) {
        cmd_disk(next_token(&p), p);
    } else if (strcasecmp(tok, "profile") == 0) {
        char *sub = next_token(&p);
        if (!sub) { outln("ERR PROFILE requires subcommand"); return; }
        if (strcasecmp(sub, "list") == 0) cmd_profile_list();
        else if (strcasecmp(sub, "select") == 0) cmd_profile_select(next_token(&p));
        else if (strcasecmp(sub, "create") == 0) {
            char *id = next_token(&p);
            cmd_profile_create(id, next_token(&p));
        }
        else if (strcasecmp(sub, "rename") == 0) {
            char *id = next_token(&p);
            cmd_profile_rename(id, next_token(&p));
        }
        else if (strcasecmp(sub, "erase") == 0) cmd_profile_erase(next_token(&p));
        else outln("ERR unknown PROFILE subcommand");
    } else if (strcasecmp(tok, "timeout") == 0) {
        cmd_timeout(next_token(&p));
    } else if (strcasecmp(tok, "reset") == 0) {
        cmd_reset(next_token(&p));
    } else {
        outln("ERR unknown command (try HELP)");
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */
void fj_console_init(void) {
    /* NOTE: must not print here. out() calls tud_task(), but fj_console_init()
     * runs before tud_init(), so any TinyUSB call before the stack is up would
     * crash. The banner is printed from the main loop once USB is ready. */
    line_len = 0;
    last_was_cr = false;
    clear_line();
}

void fj_console_task(void) {
    if (tud_cdc_connected()) {
        if (!was_connected) {
            /* First connect: print the banner and a prompt. */
            outln("Fjaeger serial console");
            outln("Type HELP for commands.");
            out(PROMPT);
            was_connected = true;
        }
    } else {
        was_connected = false;
        return;
    }

    while (tud_cdc_available()) {
        char c;
        tud_cdc_read(&c, 1);

        if (c == '\n' && last_was_cr) {
            last_was_cr = false;
            continue;
        }
        if (c == '\n' || c == '\r') {
            last_was_cr = c == '\r';
            if (line_len > 0) {
                line[line_len] = '\0';
                dispatch(line);
                line_len = 0;
                clear_line();
            }
            /* Always present a fresh prompt after a command line. */
            out(PROMPT);
        } else if (line_len < LINE_MAX - 1) {
            last_was_cr = false;
            line[line_len++] = c;
        } else {
            line_len = 0; /* line too long, discard */
            clear_line();
            out(PROMPT);
        }
    }
}
