/*
 * Fjaeger - serial console (USB CDC).
 *
 * Command interface:
 *   HELP
 *   STATUS
 *   LOCK
 *   UNLOCK <passphrase>
 *   SETPASS <passphrase>
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

/* Build version, injected by CMake (git describe --always --tags --dirty).
 * Fallback for builds not configured through CMake (e.g. host test targets). */
#ifndef FJ_VERSION_STRING
#define FJ_VERSION_STRING "dev"
#endif
#include "pico/bootrom.h"
#include "hardware/watchdog.h"

#include "state.h"
#include "crypto.h"
#include "keys.h"
#include "job.h"
#include "ctap2.h"
#include "msc_disk.h"
#include "rgb_led.h"

#define LINE_MAX 96

#define PROMPT "fjaeger> "

static char line[LINE_MAX];
static size_t line_len = 0;
static bool was_connected = false;
static bool last_was_cr = false;

/* Secret-entry mode: the device echoes input itself (so the terminal's local
 * echo can stay OFF), masking secret characters with '*', and requiring two
 * matching entries for the set/change commands. */
typedef enum {
    SEC_NONE,
    SEC_SETPASS, SEC_SETPIN, SEC_SETPUK, SEC_DISK_SETPIN,
    SEC_UNLOCK, SEC_UNLOCKPUK, SEC_DISK_UNLOCK,
} sec_action_t;
static sec_action_t pending_secret = SEC_NONE;
static char secret1[LINE_MAX], secret2[LINE_MAX];
static size_t secret1_len = 0, secret2_len = 0;
static bool secret_confirm_phase = false;   /* entering 2nd (confirm) entry */

/* Cooperative job currently executing (long PBKDF2 operations). A command
 * handler starts a job and fj_console_task() pumps it one bounded chunk per
 * main-loop tick, so the main loop's top-of-loop tud_task() keeps USB alive
 * during the multi-second derivation. */
static fj_state_job_t state_job;
static fj_disk_job_t disk_job;
static bool job_active = false;
static bool job_is_disk = false;

/* ------------------------------------------------------------------ */
/* Line output (respects CDC back-pressure)                            */
/* ------------------------------------------------------------------ */
static void out(const char *s) {
    while (*s) {
        if (!tud_cdc_connected()) return;
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

/* Character echo for interactive input (device echoes; terminal local echo
 * stays off). */
static void echo_char(char c) {
    while (!tud_cdc_write_available()) {
        if (!tud_cdc_connected()) return;
        tud_cdc_write_flush();
        tud_task();
        tight_loop_contents();
    }
    tud_cdc_write_char(c);
    tud_cdc_write_flush();
}

/* Erase the last displayed character (backspace-space-backspace). */
static void echo_erase(void) {
    echo_char(0x08); echo_char(' '); echo_char(0x08);
}

static const char *secret_entry_label(sec_action_t a) {
    switch (a) {
    case SEC_SETPASS:     return "Enter unlock passphrase: ";
    case SEC_SETPIN:      return "Enter CTAP2 PIN: ";
    case SEC_SETPUK:      return "Enter recovery PUK: ";
    case SEC_DISK_SETPIN: return "Enter disk PIN: ";
    case SEC_UNLOCK:      return "Passphrase: ";
    case SEC_UNLOCKPUK:   return "Recovery PUK: ";
    case SEC_DISK_UNLOCK: return "Disk PIN: ";
    default:              return ": ";
    }
}

static void begin_secret(sec_action_t a) {
    pending_secret = a;
    secret1_len = secret2_len = 0;
    secret_confirm_phase = false;
    out("\r\n");
    out(secret_entry_label(a));
}

/* Print the outcome of a finished cooperative job. */
static void job_print_result(void) {
    const fj_job_kind_t k = job_is_disk ? disk_job.kind : state_job.kind;
    const fj_job_result_t r = job_is_disk ? disk_job.result : state_job.result;
    char buf[96];
    const char *m = NULL;
    switch (r) {
    case FJ_RES_OK:
        switch (k) {
        case FJ_JOB_SETPASS:     m = "OK unlock passphrase set"; break;
        case FJ_JOB_UNLOCK:      m = "OK unlocked"; break;
        case FJ_JOB_SETPUK:      m = "OK recovery PUK set"; break;
        case FJ_JOB_UNLOCKPUK:   m = "OK unlocked via PUK"; break;
        case FJ_JOB_BACKUP:      m = "OK backup written to FJAEGER.BAK"; break;
        case FJ_JOB_RESTORE:     m = "OK restored with new passphrase and PUK"; break;
        case FJ_JOB_DISK_SETPIN: m = "OK disk pin set"; break;
        case FJ_JOB_DISK_UNLOCK: m = "OK disk unlocked"; break;
        case FJ_JOB_DISK_UNBLOCK: m = "OK disk PIN unblocked; use DISK UNLOCK <pin>"; break;
        default:                 m = "OK"; break;
        }
        break;
    case FJ_RES_BLOCKED:
        m = (k == FJ_JOB_DISK_UNLOCK)
                ? "ERR disk PIN blocked, use DISK UNBLOCK <puk>"
                : "ERR passphrase blocked, use UNLOCKPUK <puk>";
        break;
    case FJ_RES_BAD_PIN:
        {
            fj_security_t sec = {0};
            fj_keys_get_security(&sec);
            if (k == FJ_JOB_DISK_UNLOCK)
                snprintf(buf, sizeof(buf), "ERR bad disk pin (%u/%u left)",
                         (unsigned)(FJ_MAX_PIN_FAILS - sec.disk_fail),
                         (unsigned)FJ_MAX_PIN_FAILS);
            else
                snprintf(buf, sizeof(buf), "ERR bad passphrase (%u/%u left)",
                         (unsigned)(FJ_MAX_PASS_FAILS - sec.pass_fail),
                         (unsigned)FJ_MAX_PASS_FAILS);
            m = buf;
        }
        break;
    case FJ_RES_BAD_SECRET:
        switch (k) {
        case FJ_JOB_SETPASS:        m = "ERR invalid passphrase (8-64 chars) or device locked"; break;
        case FJ_JOB_SETPUK:         m = "ERR invalid PUK (8-64 chars) or device locked"; break;
        case FJ_JOB_BACKUP:         m = "ERR password must be 8-64 chars"; break;
        case FJ_JOB_RESTORE:        m = "ERR invalid passphrase/PUK (see HELP)"; break;
        case FJ_JOB_DISK_SETPIN:    m = "ERR disk pin invalid or drive locked"; break;
        default:                    m = "ERR operation not permitted here"; break;
        }
        break;
    case FJ_RES_DRIVE:
        m = "ERR drive not mounted; DISK UNLOCK <pin> first";
        break;
    case FJ_RES_WRONG_PUK: m = "ERR wrong PUK"; break;
    case FJ_RES_NO_PUK:    m = "ERR no PUK configured"; break;
    case FJ_RES_WIPED:     m = "OK too many wrong PUKs, device wiped"; break;
    default:               m = "ERR failed"; break;
    }
    outln(m);
}

/* Prevent the compiler from retaining command arguments (including PINs and
 * PUKs) in the reusable input buffer. The firmware echoes input itself and
 * masks secret entry ('*'); keep the terminal's local echo OFF so secrets are
 * not shown by the terminal. */
static void clear_line(void) {
    volatile char *p = line;
    for (size_t i = 0; i < sizeof(line); i++) p[i] = 0;
}

/* Wipe collected secrets so they do not linger in RAM. */
static void clear_secrets(void) {
    volatile char *a = secret1, *b = secret2;
    for (size_t i = 0; i < LINE_MAX; i++) { a[i] = 0; b[i] = 0; }
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
    out("Fjaeger ");
    outln(FJ_VERSION_STRING);
    outln("A USB security key: SSH/CTAP2 credentials and an encrypted drive.");
    outln("");
    outln("Concepts:");
    outln("  * The device is LOCKED or UNLOCKED. While locked, no signing,");
    outln("    enrollment or drive access is allowed. UNLOCK with the passphrase.");
    outln("  * The UNLOCK PASSPHRASE protects your SSH keys. The PUK recovers it");
    outln("    if you forget or lock it out (5 wrong attempts block it).");
    outln("  * The CTAP2 PIN is separate: it only authenticates the FIDO/WebAuthn");
    outln("    protocol (e.g. ssh-keygen -K). It does NOT unlock the device.");
    outln("  * The encrypted MSC drive has its OWN disk PIN, separate from the");
    outln("    device. It must be unlocked to mount/use it.");
    outln("  * Credentials live in named PROFILES. Only the active profile's");
    outln("    credentials can be used or discovered.");
    outln("  * Secret input (passphrase, PUK, PINs) is masked (*) and entered");
    outln("    twice to confirm for set/change commands. The device echoes your");
    outln("    input, so keep the terminal's local echo OFF.");
    outln("");
    outln("Commands:");
    outln("  HELP|?                     this help");
    outln("  STATUS                     device & disk state, active profile, timeout");
    outln("");
    outln("  LOCK                       lock the device (and close the drive)");
    outln("  UNLOCK <passphrase>        unlock the device (protects your SSH keys)");
    outln("  SETPASS <passphrase>       set or change the unlock passphrase");
    outln("  SETPIN <pin>               set/change the CTAP2 PIN (FIDO protocol only)");
    outln("  UNLOCKPUK <puk>            unlock via the recovery PUK (clears a lockout)");
    outln("  PUK <code>                 set or change the recovery PUK");
    outln("  TIMEOUT <sec>              auto-lock delay in seconds (default 900; 0 = off)");
    outln("");
    outln("  DISK STATUS                show drive lock state");
    outln("  DISK SETPIN <pin>          set or change the drive's disk PIN");
    outln("  DISK UNLOCK <pin>          unlock and mount the encrypted drive");
    outln("  DISK UNBLOCK <puk>         clear a disk-PIN lock (the disk PIN is still needed)");
    outln("  DISK LOCK                  lock and unmount the drive");
    outln("  DISK LOCK FORCE YES        discard pending writes after an I/O failure");
    outln("  DISK FORMAT YES             erase ALL drive data and rebuild the filesystem");
    outln("");
    outln("  PROFILE LIST               list profiles, the active one and credential counts");
    outln("  PROFILE CREATE <id> <name> create a new empty profile (id 0-7)");
    outln("  PROFILE SELECT <id>        select and persist the active profile");
    outln("  PROFILE RENAME <id> <name> rename a profile without touching its credentials");
    outln("  PROFILE ERASE <id>         delete a profile and every credential in it");
    outln("  CREDS LIST                 list credentials in the active profile");
    outln("  CREDS DEL <hex-id>         delete one credential from the active profile");
    outln("");
    outln("  BACKUP <password>          write an encrypted backup (keys+profiles) to the drive");
    outln("  RESTORE <pw> <pass> <puk>  restore a backup; sets a new passphrase and PUK");
    outln("");
    outln("  RESET                      reboot the device");
    outln("  RESET BOOTSEL              reboot into the USB bootloader for flashing");
    outln("");
    outln("SSH usage (OpenSSH talks to the key directly, not through this console):");
    outln("  1. Make sure the device is UNLOCKED (passphrase) and the right");
    outln("     PROFILE is SELECTED.");
    outln("  2. Enroll a resident key (on the PC):");
    outln("       ssh-keygen -t ecdsa-sk -O resident -f ~/.ssh/id_ecdsa_sk");
    outln("     The credential is bound to the currently active profile.");
    outln("  3. Use it for SSH login; the agent signs with the key on the device.");
    outln("  4. Copy a resident key back to the PC with:");
    outln("       ssh-keygen -K            (may prompt for the CTAP2 PIN)");
    outln("  5. Verify a signature (on the PC):");
    outln("       ssh-keygen -Y sign -f ~/.ssh/id_ecdsa_sk -n <ns> <file>");
    outln("       ssh-keygen -Y verify -f allowed_signers -I <name> -n <ns> \\");
    outln("                       -s <file>.sig < <file>");
    outln("  ECDSA P-256 / ES256 and Ed25519 / EdDSA security keys are supported.");
    outln("  A wrong profile returns no signature; select the owning profile first.");
    outln("");
    outln("Mutating commands (SETPASS, SETPIN, PUK, DISK SETPIN, PROFILE");
    outln("CREATE/SELECT/RENAME/ERASE, TIMEOUT, BACKUP) require the device to be");
    outln("unlocked. Five wrong passphrase/PIN attempts block; five wrong PUKs");
    outln("wipe the device (factory reset).");
}

static void cmd_status(void) {
    char buf[320];
    fj_security_t sec = {0};
    bool have_sec = fj_keys_get_security(&sec);
    snprintf(buf, sizeof(buf), "version: %s\r\n"
             "state: %s\r\n"
             "disk: %s\r\n"
             "pass_blocked: %s\r\n"
             "pass_fail: %u\r\n"
             "ctap_pin_blocked: %s\r\n"
             "ctap_pin_fail: %u\r\n"
             "disk_blocked: %s\r\n"
             "disk_fail: %u\r\n"
             "disk_flush_pending: %s\r\n"
             "puk: %s\r\n"
             "puk_fail: %u\r\n"
             "active_profile: %u\r\n"
             "profiles: %u\r\n"
             "timeout: %lus",
             FJ_VERSION_STRING,
             fj_state_get() == FJ_STATE_UNLOCKED ? "unlocked" : "locked",
             fj_msc_is_ready() ? "unlocked" : "locked",
             (have_sec && sec.pass_blocked) ? "yes" : "no", (unsigned)sec.pass_fail,
             (have_sec && sec.ctap_pin_blocked) ? "yes" : "no", (unsigned)sec.ctap_pin_fail,
             (have_sec && sec.disk_blocked) ? "yes" : "no", (unsigned)sec.disk_fail,
             fj_msc_lock_pending() ? "yes (keep powered)" : "no",
             fj_keys_puk_configured() ? "set" : "unset", (unsigned)sec.puk_fail,
             fj_keys_active_profile(), fj_keys_profile_count(),
             (unsigned long)fj_state_timeout());
    outln(buf);
}

static void cmd_lock(void) {
    fj_state_lock();
    outln(fj_msc_lock_pending()
          ? "ERR device locked; disk flush pending, keep powered"
          : "OK locked");
}

static void do_unlock(const char *passphrase) {
    if (fj_state_pass_blocked()) {
        outln("ERR passphrase blocked, use UNLOCKPUK <puk>");
        return;
    }
    fj_state_job_start(&state_job, FJ_JOB_UNLOCK, passphrase, NULL, NULL);
    job_active = true;
    job_is_disk = false;
}

static void cmd_unlock(const char *passphrase) {
    if (!passphrase) { begin_secret(SEC_UNLOCK); return; }
    do_unlock(passphrase);
}

static void do_unlock_puk(const char *puk) {
    fj_state_job_start(&state_job, FJ_JOB_UNLOCKPUK, puk, NULL, NULL);
    job_active = true;
    job_is_disk = false;
}

static void cmd_unlock_puk(const char *puk) {
    if (!puk) { begin_secret(SEC_UNLOCKPUK); return; }
    do_unlock_puk(puk);
}

static bool require_unlocked(void);

static void do_set_puk(const char *puk) {
    if (!require_unlocked()) return;
    if (strlen(puk) < 8 || strlen(puk) > 64) {
        outln("ERR invalid PUK (8-64 chars) or device locked");
        return;
    }
    fj_state_job_start(&state_job, FJ_JOB_SETPUK, puk, NULL, NULL);
    job_active = true;
    job_is_disk = false;
}

static void cmd_set_puk(const char *puk) {
    if (!puk) { begin_secret(SEC_SETPUK); return; }
    do_set_puk(puk);
}

/* BACKUP <password> — write an encrypted backup of the master key and all
 * credentials/profiles to the MSC drive as FJAEGER.BAK. Requires the device
 * unlocked (so the master key is available). The file is deleted on lock. */
static void cmd_backup(const char *password) {
    if (!password) {
        outln("ERR usage: BACKUP <password>");
        return;
    }
    if (!require_unlocked()) return;
    if (strlen(password) < 8 || strlen(password) > 64) {
        outln("ERR password must be 8-64 chars");
        return;
    }
    if (!fj_msc_is_ready()) {
        outln("ERR drive not mounted; DISK UNLOCK <pin> first");
        return;
    }
    fj_state_job_start(&state_job, FJ_JOB_BACKUP, password, NULL, NULL);
    job_active = true;
    job_is_disk = false;
}

/* RESTORE <password> <new-pin> <new-puk> — read FJAEGER.BAK from the MSC
 * drive, decrypt it and import the credentials/profiles/master key, setting
 * a new PIN and PUK in one step. */
static void cmd_restore(const char *password, const char *new_pass,
                        const char *new_puk) {
    if (!password || !new_pass || !new_puk) {
        outln("ERR usage: RESTORE <password> <new-passphrase> <new-puk>");
        return;
    }
    if (strlen(password) < 8 || strlen(password) > 64) {
        outln("ERR password must be 8-64 chars");
        return;
    }
    if (!fj_msc_is_ready()) {
        outln("ERR drive not mounted; DISK UNLOCK <pin> first");
        return;
    }
    fj_state_job_start(&state_job, FJ_JOB_RESTORE, password, new_pass, new_puk);
    job_active = true;
    job_is_disk = false;
}

static void do_disk_unlock(const char *pin) {
    if (fj_msc_pin_blocked()) {
        outln("ERR disk PIN blocked, use DISK UNBLOCK <puk>");
        return;
    }
    fj_disk_job_start(&disk_job, FJ_JOB_DISK_UNLOCK, pin);
    job_active = true;
    job_is_disk = true;
}

static void do_disk_setpin(const char *pin) {
    size_t n = strlen(pin);
    if (n < 4 || n > 32) { outln("ERR disk pin invalid or drive locked"); return; }
    fj_disk_job_start(&disk_job, FJ_JOB_DISK_SETPIN, pin);
    job_active = true;
    job_is_disk = true;
}

/* DISK UNLOCK <pin> / SETPIN <pin> / LOCK / STATUS — independent drive lock. */
static void cmd_disk(const char *sub, char *rest) {
    if (!sub) {
        outln("ERR DISK requires subcommand (UNLOCK|UNBLOCK|LOCK|SETPIN|STATUS|FORMAT)");
        return;
    }
    if (strcasecmp(sub, "status") == 0) {
        char buf[128];
        fj_security_t sec = {0};
        fj_keys_get_security(&sec);
        snprintf(buf, sizeof(buf), "disk: %s%s\r\n"
                 "disk_fail: %u\r\nflush_pending: %s",
                 fj_msc_is_ready() ? "unlocked" : "locked",
                 sec.disk_blocked ? " (PIN blocked, use DISK UNBLOCK)" : "",
                 (unsigned)sec.disk_fail,
                 fj_msc_lock_pending() ? "yes (keep powered)" : "no");
        outln(buf);
    } else if (strcasecmp(sub, "unlock") == 0) {
        if (!require_unlocked()) return;
        const char *pin = next_token(&rest);
        if (!pin) { begin_secret(SEC_DISK_UNLOCK); return; }
        do_disk_unlock(pin);
    } else if (strcasecmp(sub, "unblock") == 0) {
        if (!require_unlocked()) return;
        const char *puk = next_token(&rest);
        if (!puk) { outln("ERR usage: DISK UNBLOCK <puk>"); return; }
        fj_disk_job_start(&disk_job, FJ_JOB_DISK_UNBLOCK, puk);
        job_active = true;
        job_is_disk = true;
    } else if (strcasecmp(sub, "lock") == 0) {
        const char *mode = next_token(&rest);
        if (mode) {
            const char *confirm = next_token(&rest);
            if (strcasecmp(mode, "force") != 0 || !confirm ||
                strcasecmp(confirm, "yes") != 0) {
                outln("ERR usage: DISK LOCK FORCE YES");
                return;
            }
            fj_msc_force_lock();
            outln("OK disk locked; pending writes discarded");
            return;
        }
        fj_msc_lock();
        outln(fj_msc_lock_pending()
              ? "ERR disk closed; flush pending, keep powered or use DISK LOCK FORCE YES"
              : "OK disk locked");
    } else if (strcasecmp(sub, "setpin") == 0) {
        if (!require_unlocked()) return;
        const char *pin = next_token(&rest);
        if (!pin) { begin_secret(SEC_DISK_SETPIN); return; }
        do_disk_setpin(pin);
    } else if (strcasecmp(sub, "format") == 0) {
        if (!require_unlocked()) return;
        const char *tok = next_token(&rest);
        if (!tok || strcasecmp(tok, "YES") != 0) {
            outln("ERR mutating; type DISK FORMAT YES to erase all drive data");
            return;
        }
        if (!fj_keys_disk_secret_set()) {
            outln("ERR no disk key; use DISK SETPIN <pin> first");
            return;
        }
        if (!fj_msc_format()) {
            outln("ERR drive not mounted; DISK UNLOCK <pin> first");
            return;
        }
        outln("OK drive formatted (all data erased)");
    } else {
        outln("ERR unknown DISK subcommand (UNLOCK|UNBLOCK|LOCK|SETPIN|STATUS|FORMAT)");
    }
}

static void do_setpin(const char *pin) {
    if (fj_state_set_ctap2_pin(pin)) {
        outln("OK CTAP2 PIN set");
    } else {
        outln("ERR invalid CTAP2 PIN or device locked");
    }
}

static void cmd_setpin(const char *pin) {
    if (!pin) { begin_secret(SEC_SETPIN); return; }
    do_setpin(pin);
}

static void do_setpass(const char *passphrase) {
    size_t n = strlen(passphrase);
    if (n < 8 || n > 64) {
        outln("ERR invalid passphrase (8-64 chars)");
        return;
    }
    fj_state_job_start(&state_job, FJ_JOB_SETPASS, passphrase, NULL, NULL);
    job_active = true;
    job_is_disk = false;
}

static void cmd_setpass(const char *passphrase) {
    if (!passphrase) { begin_secret(SEC_SETPASS); return; }
    do_setpass(passphrase);
}

static bool require_unlocked(void) {
    if (fj_state_get() == FJ_STATE_UNLOCKED) return true;
    outln("ERR device locked");
    return false;
}

/* Only the set/change commands require two matching (masked) entries. */
static bool action_needs_confirm(sec_action_t a) {
    return a == SEC_SETPASS || a == SEC_SETPIN ||
           a == SEC_SETPUK || a == SEC_DISK_SETPIN;
}

/* Apply a collected secret to the pending masked-entry action. */
static void run_secret(sec_action_t a, const char *s) {
    switch (a) {
    case SEC_SETPASS:     do_setpass(s); break;
    case SEC_SETPIN:      do_setpin(s); break;
    case SEC_SETPUK:      do_set_puk(s); break;
    case SEC_DISK_SETPIN: do_disk_setpin(s); break;
    case SEC_UNLOCK:      do_unlock(s); break;
    case SEC_UNLOCKPUK:   do_unlock_puk(s); break;
    case SEC_DISK_UNLOCK: do_disk_unlock(s); break;
    default:              break;
    }
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

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char *credential_type(const fj_ctap2_cred_t *cred) {
    if (cred->public_key[0] == FJ_PUBKEY_ED25519) return "ed25519-sk";
    if (cred->public_key[0] == FJ_PUBKEY_P256) return "ecdsa-sk";
    return "unknown";
}

static bool ssh_wire_string(uint8_t *buf, size_t cap, size_t *pos,
                            const uint8_t *value, size_t len) {
    if (len > UINT32_MAX || *pos > cap - 4 || len > cap - *pos - 4)
        return false;
    uint32_t n = (uint32_t)len;
    buf[(*pos)++] = (uint8_t)(n >> 24);
    buf[(*pos)++] = (uint8_t)(n >> 16);
    buf[(*pos)++] = (uint8_t)(n >> 8);
    buf[(*pos)++] = (uint8_t)n;
    memcpy(buf + *pos, value, len);
    *pos += len;
    return true;
}

/* Return the base64(SHA256(SSH public-key blob)) portion of an OpenSSH
 * fingerprint. The application is part of an SSH security-key public blob,
 * so a non-resident credential cannot have a matching fingerprint here: its
 * clear-text application lives only in the OpenSSH stub. */
static bool ssh_fingerprint(const fj_ctap2_cred_t *cred, char out[44]) {
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const uint8_t ed_type[] = "sk-ssh-ed25519@openssh.com";
    static const uint8_t ec_type[] = "sk-ecdsa-sha2-nistp256@openssh.com";
    static const uint8_t curve[] = "nistp256";
    uint8_t blob[192], digest[32];
    size_t pos = 0;
    size_t app_len = cred->rp_len;
    if (app_len == 0 || app_len > FJ_RP_MAX) return false;

    if (cred->public_key[0] == FJ_PUBKEY_ED25519) {
        if (!ssh_wire_string(blob, sizeof(blob), &pos, ed_type,
                             sizeof(ed_type) - 1) ||
            !ssh_wire_string(blob, sizeof(blob), &pos, cred->public_key + 1, 32))
            return false;
    } else if (cred->public_key[0] == FJ_PUBKEY_P256) {
        if (!ssh_wire_string(blob, sizeof(blob), &pos, ec_type,
                             sizeof(ec_type) - 1) ||
            !ssh_wire_string(blob, sizeof(blob), &pos, curve, sizeof(curve) - 1) ||
            !ssh_wire_string(blob, sizeof(blob), &pos, cred->public_key + 1, 65))
            return false;
    } else {
        return false;
    }
    if (!ssh_wire_string(blob, sizeof(blob), &pos, cred->rp, app_len)) return false;
    fj_sha256(blob, pos, digest);
    size_t o = 0;
    for (size_t i = 0; i < sizeof(digest); i += 3) {
        uint32_t v = (uint32_t)digest[i] << 16;
        if (i + 1 < sizeof(digest)) v |= (uint32_t)digest[i + 1] << 8;
        if (i + 2 < sizeof(digest)) v |= digest[i + 2];
        out[o++] = b64[(v >> 18) & 63];
        out[o++] = b64[(v >> 12) & 63];
        out[o++] = i + 1 < sizeof(digest) ? b64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < sizeof(digest) ? b64[v & 63] : '=';
    }
    out[43] = '\0'; /* OpenSSH omits the final '=' padding for SHA-256. */
    return true;
}

/* CREDS LIST / CREDS DEL <hex-id> — manage the credentials in the ACTIVE
 * profile only. */
static void cmd_creds(const char *sub, char *rest) {
    char buf[224];
    if (!sub) { outln("ERR CREDS requires subcommand (LIST|DEL)"); return; }

    if (strcasecmp(sub, "list") == 0) {
        fj_ctap2_cred_t creds[FJ_CTAP2_CREDS];
        fj_keys_ctap2_load(creds);
        unsigned active = fj_keys_active_profile();
        unsigned n = 0;
        for (unsigned i = 0; i < FJ_CTAP2_CREDS; i++) {
            if (!creds[i].in_use || creds[i].profile_id != active) continue;
            char idhex[FJ_CRED_ID_LEN * 2 + 1];
            unsigned j;
            for (j = 0; j < FJ_CRED_ID_LEN; j++)
                snprintf(idhex + j * 2, 3, "%02x", creds[i].credential_id[j]);
            idhex[FJ_CRED_ID_LEN * 2] = '\0';
            if (creds[i].rp_len > 0) {
                int application_len = creds[i].rp_len <= FJ_RP_MAX
                                          ? (int)creds[i].rp_len
                                          : FJ_RP_MAX;
                char fingerprint[44];
                bool have_fingerprint = ssh_fingerprint(&creds[i], fingerprint);
                snprintf(buf, sizeof(buf),
                         "  [%02u] type=%s application=%.*s resident=%s fp=%s id=%s",
                         i, credential_type(&creds[i]), application_len,
                         (const char *)creds[i].rp,
                         creds[i].resident ? "yes" : "no",
                         have_fingerprint ? fingerprint : "<unavailable>", idhex);
            } else {
                /* Non-resident credentials retain only the RP hash; their
                 * clear-text application is held by the OpenSSH key stub. */
                snprintf(buf, sizeof(buf),
                         "  [%02u] type=%s application=<not-stored> resident=%s fp=<unavailable> id=%s",
                         i, credential_type(&creds[i]),
                         creds[i].resident ? "yes" : "no", idhex);
            }
            outln(buf);
            n++;
        }
        snprintf(buf, sizeof(buf), "%u credential(s) in active profile %u", n, active);
        outln(buf);
        return;
    }

    if (strcasecmp(sub, "del") == 0) {
        const char *id = next_token(&rest);
        const char *conf = next_token(&rest);
        if (!id) { outln("ERR usage: CREDS DEL <hex-id> yes"); return; }
        if (!conf || strcasecmp(conf, "yes") != 0) {
            outln("ERR mutating; type CREDS DEL <hex-id> yes");
            return;
        }
        if (strlen(id) != FJ_CRED_ID_LEN * 2) {
            outln("ERR invalid credential id (need 32 hex chars)");
            return;
        }
        uint8_t idb[FJ_CRED_ID_LEN];
        for (unsigned j = 0; j < FJ_CRED_ID_LEN; j++) {
            int hi = hex_val(id[j * 2]);
            int lo = hex_val(id[j * 2 + 1]);
            if (hi < 0 || lo < 0) { outln("ERR invalid credential id (non-hex)"); return; }
            idb[j] = (uint8_t)((hi << 4) | lo);
        }
        unsigned active = fj_keys_active_profile();
        if (fj_ctap2_delete_cred(active, idb))
            outln("OK credential deleted from active profile");
        else
            outln("ERR credential not found in active profile");
        return;
    }

    outln("ERR unknown CREDS subcommand (LIST|DEL)");
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
    } else if (strcasecmp(tok, "setpass") == 0) {
        cmd_setpass(next_token(&p));
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
    } else if (strcasecmp(tok, "creds") == 0) {
        cmd_creds(next_token(&p), p);
    } else if (strcasecmp(tok, "timeout") == 0) {
        cmd_timeout(next_token(&p));
    } else if (strcasecmp(tok, "backup") == 0) {
        cmd_backup(next_token(&p));
    } else if (strcasecmp(tok, "restore") == 0) {
        cmd_restore(next_token(&p), next_token(&p), next_token(&p));
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
            out("Fjaeger ");
            outln(FJ_VERSION_STRING);
            outln("Type HELP for commands.");
            out(PROMPT);
            was_connected = true;
        }
    } else {
        was_connected = false;
        return;
    }

    /* Pump an active cooperative job (long PBKDF2) a bounded chunk per
     * main-loop tick; the main loop's top-of-loop tud_task() services USB
     * between chunks. */
    if (job_active) {
        bool done = job_is_disk ? !fj_disk_job_step(&disk_job)
                                : !fj_state_job_step(&state_job);
        if (done) {
            job_print_result();
            job_active = false;
            out(PROMPT);
        }
        return;
    }

    while (tud_cdc_available()) {
        char c;
        tud_cdc_read(&c, 1);
        if (c == 0x7f) c = 0x08;   /* DEL ~ backspace */

        if (c == '\n' && last_was_cr) { last_was_cr = false; continue; }

        if (pending_secret != SEC_NONE) {
            char *buf = secret_confirm_phase ? secret2 : secret1;
            size_t *len = secret_confirm_phase ? &secret2_len : &secret1_len;
            if (c == 0x03 || c == 0x1b) {   /* Ctrl-C / ESC: cancel */
                pending_secret = SEC_NONE;
                secret1_len = secret2_len = 0;
                clear_secrets();
                out("\r\nOK cancelled\r\n");
                out(PROMPT);
                continue;
            }
            if (c == 0x08) {
                if (*len > 0) { (*len)--; echo_erase(); }
                continue;
            }
            if (c == '\r' || c == '\n') {
                last_was_cr = (c == '\r');
                out("\r\n");
                if (secret_confirm_phase) {
                    sec_action_t act = pending_secret;
                    if (secret1_len == secret2_len &&
                        memcmp(secret1, secret2, secret1_len) == 0) {
                        pending_secret = SEC_NONE;
                        secret1[secret1_len] = '\0';
                        run_secret(act, secret1);
                        clear_secrets();
                    } else {
                        outln("ERR entries did not match; try again");
                        secret_confirm_phase = false;
                        secret1_len = 0;
                        clear_secrets();
                        out(secret_entry_label(act));
                    }
                    secret2_len = 0;
                } else if (action_needs_confirm(pending_secret)) {
                    secret_confirm_phase = true;
                    out("Confirm: ");
                } else {
                    sec_action_t act = pending_secret;
                    pending_secret = SEC_NONE;
                    secret1[secret1_len] = '\0';
                    run_secret(act, secret1);
                    clear_secrets();
                }
                if (job_active) return;
                continue;
            }
            if (*len < LINE_MAX - 1) {
                buf[(*len)++] = c;
                echo_char('*');
            }
            continue;
        }

        if (c == '\r' || c == '\n') {
            last_was_cr = (c == '\r');
            echo_char('\r'); echo_char('\n');
            if (line_len > 0) {
                line[line_len] = '\0';
                dispatch(line);
                line_len = 0;
                clear_line();
            }
            if (job_active) return;
            if (!job_active && pending_secret == SEC_NONE) out(PROMPT);
        } else if (c == 0x08) {
            last_was_cr = false;
            if (line_len > 0) { line_len--; echo_erase(); }
        } else if (line_len < LINE_MAX - 1) {
            last_was_cr = false;
            echo_char(c);
            line[line_len++] = c;
        } else {
            last_was_cr = false;
            line_len = 0;
            clear_line();
            out("\r\n");
            out(PROMPT);
        }
    }
}
