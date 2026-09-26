/*
 * Fjaeger - serial console (USB CDC) interface.
 */
#ifndef FJAEGER_CDC_CONSOLE_H
#define FJAEGER_CDC_CONSOLE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the console and print a banner. */
void fj_console_init(void);

/* Process inbound serial data. Call from the main loop. */
void fj_console_task(void);

#ifdef __cplusplus
}
#endif

#endif /* FJAEGER_CDC_CONSOLE_H */