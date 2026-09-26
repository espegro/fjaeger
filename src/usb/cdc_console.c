/*
 * Fjaeger - serial console (USB CDC).
 *
 * Command interface:
 *   HELP
 *   STATUS
 *   LOCK
 *   UNLOCK <pin>
 *   SETPIN <pin>
 *   KEY LIST
 *   KEY SELECT <n>
 *   KEY PROVISION <n> [name]     (generates fresh keys)
 *   KEY ERASE <n>
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
#include "hardware/watchdog.h"

#include "state.h"
#include "keys.h"
#include "msc_disk.h"
#include "rgb_led.h"

#define LINE_MAX 96

static char line[LINE_MAX];
static size_t line_len = 0;

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
    outln("  STATUS                     show state, active slot, slots, timeout");
    outln("  LOCK                       lock the device immediately");
    outln("  UNLOCK <pin>               unlock with PIN");
    outln("  SETPIN <pin>               set/change PIN");
    outln("  TIMEOUT <sec>              auto-relock after sec (0 = off)");
    outln("  RESET                      reboot the device");
    outln("  KEY LIST                   list all 8 slots");
    outln("  KEY SELECT <n>             set active slot (0-7)");
    outln("  KEY PROVISION <n> [name]   generate fresh key in slot n");
    outln("  KEY ERASE <n>              erase slot n");
}

static void cmd_status(void) {
    char buf[96];
    snprintf(buf, sizeof(buf), "state: %s\r\n"
             "active_slot: %u\r\n"
             "provisioned_slots: %u\r\n"
             "timeout: %lus",
             fj_state_get() == FJ_STATE_UNLOCKED ? "unlocked" : "locked",
             fj_keys_active_slot(), fj_keys_count(),
             (unsigned long)fj_state_timeout());
    outln(buf);
}

static void cmd_lock(void) {
    fj_state_lock();
    fj_msc_set_ready(false);
    outln("OK locked");
}

static void cmd_unlock(const char *pin) {
    if (!pin) {
        outln("ERR usage: UNLOCK <pin>");
        return;
    }
    if (fj_state_unlock(pin)) {
        /* Re-mount the decrypted drive with the active slot. */
        fj_msc_set_ready(true);
        outln("OK unlocked");
    } else {
        outln("ERR bad pin or no pin set");
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

static void cmd_key_list(void) {
    char buf[96];
    unsigned count = fj_keys_count();
    for (unsigned i = 0; i < FJ_NUM_SLOTS; i++) {
        const fj_slot_t *s = fj_keys_get(i);
        snprintf(buf, sizeof(buf), "slot %u: %s",
                 i, s ? s->name : "(empty)");
        outln(buf);
    }
    (void)count;
}

static void cmd_key_select(const char *arg) {
    if (!require_unlocked()) return;
    if (!arg) {
        outln("ERR usage: KEY SELECT <n>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_SLOTS) {
        outln("ERR invalid slot");
        return;
    }
    unsigned n = (unsigned)parsed;
    if (fj_keys_set_active_slot(n)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OK active slot = %u", n);
        outln(buf);
    } else {
        outln("ERR slot not provisioned or out of range");
    }
}

static void cmd_key_provision(const char *arg, const char *name) {
    if (!require_unlocked()) return;
    unsigned n;
    if (!arg) {
        outln("ERR usage: KEY PROVISION <n> [name]");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_SLOTS) {
        outln("ERR invalid slot");
        return;
    }
    n = (unsigned)parsed;

    if (fj_keys_provision(n, name ? name : "key", true)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "OK provisioned slot %u", n);
        outln(buf);
    } else {
        outln("ERR provision failed");
    }
}

static void cmd_key_erase(const char *arg) {
    if (!require_unlocked()) return;
    if (!arg) {
        outln("ERR usage: KEY ERASE <n>");
        return;
    }
    unsigned long parsed;
    if (!parse_uint(arg, &parsed) || parsed >= FJ_NUM_SLOTS) {
        outln("ERR invalid slot");
        return;
    }
    unsigned n = (unsigned)parsed;
    bool was_active = n == fj_keys_active_slot();
    if (fj_keys_erase(n)) {
        if (was_active) {
            fj_state_lock();
            fj_msc_set_ready(false);
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "OK erased slot %u", n);
        outln(buf);
    } else {
        outln("ERR erase failed");
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
    fj_state_set_timeout(sec);
    char buf[64];
    snprintf(buf, sizeof(buf), "OK timeout = %lus", (unsigned long)sec);
    outln(buf);
}

static void cmd_reset(void) {
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
    } else if (strcasecmp(tok, "setpin") == 0) {
        cmd_setpin(next_token(&p));
    } else if (strcasecmp(tok, "key") == 0) {
        char *sub = next_token(&p);
        if (!sub) { outln("ERR KEY requires subcommand"); return; }
        if (strcasecmp(sub, "list") == 0) cmd_key_list();
        else if (strcasecmp(sub, "select") == 0) cmd_key_select(next_token(&p));
        else if (strcasecmp(sub, "provision") == 0) {
            char *slot = next_token(&p);
            cmd_key_provision(slot, next_token(&p));
        }
        else if (strcasecmp(sub, "erase") == 0) cmd_key_erase(next_token(&p));
        else outln("ERR unknown KEY subcommand");
    } else if (strcasecmp(tok, "timeout") == 0) {
        cmd_timeout(next_token(&p));
    } else if (strcasecmp(tok, "reset") == 0) {
        cmd_reset();
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
}

void fj_console_task(void) {
    if (!tud_cdc_connected()) return;

    while (tud_cdc_available()) {
        char c;
        tud_cdc_read(&c, 1);

        if (c == '\n' || c == '\r') {
            if (line_len > 0) {
                line[line_len] = '\0';
                dispatch(line);
                line_len = 0;
            }
        } else if (line_len < LINE_MAX - 1) {
            line[line_len++] = c;
        } else {
            line_len = 0; /* line too long, discard */
        }
    }
}
