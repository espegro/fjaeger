/*
 * Fjaeger - USB descriptors.
 *
 * Composite device exposing three interfaces:
 *   1. CDC  - serial console (lock / unlock / key select / ...)
 *   2. HID  - FIDO U2F authenticator (raw 64-byte reports)
 *   3. MSC  - encrypted mass storage drive
 */
#include "tusb.h"
#include "bsp/board_api.h"

/* ------------------------------------------------------------------ */
/* VID/PID                                                             */
/* ------------------------------------------------------------------ */
#define USB_VID 0x2E8A  /* Raspberry Pi VID (experimental use) */
#define USB_BCD 0x0200

/* A combination of interfaces must have a unique product id. */
#define _PID_MAP(itf, n) ((CFG_TUD_##itf) << (n))
#define USB_PID (0x4000 | _PID_MAP(CDC, 0) | _PID_MAP(MSC, 1) | _PID_MAP(HID, 2))

/* ------------------------------------------------------------------ */
/* Device descriptor                                                   */
/* ------------------------------------------------------------------ */
tusb_desc_device_t const desc_device = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = USB_BCD,
    .bDeviceClass       = 0x00,  /* defined per-interface (composite) */
    .bDeviceSubClass    = 0x00,
    .bDeviceProtocol    = 0x00,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = USB_VID,
    .idProduct          = USB_PID,
    .bcdDevice          = 0x0100,
    .iManufacturer      = 0x01,
    .iProduct           = 0x02,
    .iSerialNumber      = 0x03,
    .bNumConfigurations = 0x01,
};

uint8_t const *tud_descriptor_device_cb(void) {
    return (uint8_t const *)&desc_device;
}

/* ------------------------------------------------------------------ */
/* Configuration descriptor                                            */
/* ------------------------------------------------------------------ */
enum {
    ITF_NUM_CDC = 0,
    ITF_NUM_CDC_DATA,
    ITF_NUM_HID,
    ITF_NUM_MSC,
    ITF_NUM_TOTAL,
};

enum {
    EPNUM_CDC_NOTIF = 0x81,   /* EP1 IN  */
    EPNUM_CDC_OUT   = 0x02,   /* EP2 OUT */
    EPNUM_CDC_IN    = 0x82,   /* EP2 IN  */

    EPNUM_HID_OUT   = 0x03,   /* EP3 OUT */
    EPNUM_HID_IN    = 0x83,   /* EP3 IN  */

    EPNUM_MSC_OUT   = 0x04,   /* EP4 OUT */
    EPNUM_MSC_IN    = 0x84,   /* EP4 IN  */
};

#define CONFIG_TOTAL_LEN (TUD_CONFIG_DESC_LEN + TUD_CDC_DESC_LEN + \
                          TUD_HID_INOUT_DESC_LEN + TUD_MSC_DESC_LEN)

/* FIDO U2F report descriptor: raw 64-byte IN/OUT reports. */
#define FIDO_REPORT_SIZE 64
const uint8_t desc_hid_report[] = {
    TUD_HID_REPORT_DESC_FIDO_U2F(FIDO_REPORT_SIZE),
};

uint8_t const desc_fs_configuration[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, CONFIG_TOTAL_LEN,
                          TUSB_DESC_CONFIG_ATT_SELF_POWERED, 100),

    /* CDC */
    TUD_CDC_DESCRIPTOR(ITF_NUM_CDC, 4, EPNUM_CDC_NOTIF, 8,
                       EPNUM_CDC_OUT, EPNUM_CDC_IN, 64),

    /* HID (FIDO U2F) */
    TUD_HID_INOUT_DESCRIPTOR(ITF_NUM_HID, 5, HID_ITF_PROTOCOL_NONE,
                             sizeof(desc_hid_report),
                             EPNUM_HID_OUT, EPNUM_HID_IN,
                             CFG_TUD_HID_EP_BUFSIZE, 10),

    /* MSC */
    TUD_MSC_DESCRIPTOR(ITF_NUM_MSC, 6, EPNUM_MSC_OUT, EPNUM_MSC_IN, 64),
};

uint8_t const *tud_descriptor_configuration_cb(uint8_t index) {
    (void)index;
    return desc_fs_configuration;
}

/* ------------------------------------------------------------------ */
/* String descriptors                                                  */
/* ------------------------------------------------------------------ */
enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
};

char const *string_desc_arr[] = {
    (const char[]){0x09, 0x04}, /* 0: English (0x0409) */
    "Fjaeger",                  /* 1: Manufacturer */
    "Fjaeger Security Key",     /* 2: Product */
    NULL,                       /* 3: Serial (from unique id) */
    "Fjaeger Console",          /* 4: CDC interface */
    "Fjaeger U2F",              /* 5: HID interface */
    "Fjaeger Drive",            /* 6: MSC interface */
};

static uint16_t _desc_str[32 + 1];

uint16_t const *tud_descriptor_string_cb(uint8_t index, uint16_t langid) {
    (void)langid;
    size_t chr_count;

    switch (index) {
        case STRID_LANGID:
            memcpy(&_desc_str[1], string_desc_arr[0], 2);
            chr_count = 1;
            break;

        case STRID_SERIAL:
            chr_count = board_usb_get_serial(_desc_str + 1, 32);
            break;

        default:
            if (!(index < sizeof(string_desc_arr) / sizeof(string_desc_arr[0])))
                return NULL;

            const char *str = string_desc_arr[index];
            chr_count = strlen(str);
            size_t const max_count = sizeof(_desc_str) / sizeof(_desc_str[0]) - 1;
            if (chr_count > max_count) chr_count = max_count;

            for (size_t i = 0; i < chr_count; i++) {
                _desc_str[1 + i] = str[i];
            }
            break;
    }

    _desc_str[0] = (uint16_t)((TUSB_DESC_STRING << 8) | (2 * chr_count + 2));
    return _desc_str;
}