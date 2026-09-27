cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(fjaeger C CXX)

# ---------------------------------------------------------------------
# Board / toolchain
# ---------------------------------------------------------------------
# TENSTAR RP2350-USB 16 MB dongle: electrically compatible with the
# Waveshare RP2350-Plus 16 MB profile. NOTE: this board requires Pico SDK
# 2.1.0+ (TinyUSB with RP2350 support). Configure with
#   -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk  (2.2.0)
set(PICO_BOARD waveshare_rp2350_plus_16mb)
set(PICO_CMAKE_FLAGS "-DPICO_CYW43_SUPPORTED=0")

# mbedTLS config: start from the default mbedTLS 3.x config and add the
# Pico-specific settings (hardware RNG + SHA-256 accelerator) via a wrapper.
# (The previous custom config targeted mbedTLS 2.28 and X.509 attestation,
# which has been removed - CTAP2 uses attestation format "none".)
set(PICO_MBEDTLS_CONFIG_FILE "fjaeger_mbedtls_config.h")

pico_sdk_init()

# ---------------------------------------------------------------------
# Core target (device firmware)
# ---------------------------------------------------------------------
add_executable(fjaeger
  src/main.c
  src/usb/usb_descriptors.c
  src/usb/msc_disk.c
  src/usb/cdc_console.c
  src/core/state.c
  src/core/keys.c
  src/core/crypto.c
  src/core/ms_time.c
  src/led/rgb_led.c
  src/fido/u2f.c
  src/fido/ctap2.c
  src/fido/cbor.c
  src/fido/pin.c
)

target_include_directories(fjaeger PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/usb
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core
  ${CMAKE_CURRENT_SOURCE_DIR}/src/fido
  ${CMAKE_CURRENT_SOURCE_DIR}/src/led
  ${CMAKE_CURRENT_SOURCE_DIR}/src/mbedtls_config
)

# TinyUSB selects its config header by name from the include path
target_compile_definitions(fjaeger PRIVATE
  CFG_TUSB_CONFIG_FILE="tusb_config.h"
  PICO_FLASH_SIZE_BYTES=0x1000000
  # mbedTLS P-256 signing plus CTAP2 request/response buffers exceed the
  # Pico SDK's 2 KiB default stack and otherwise wedge USB in getAssertion.
  PICO_STACK_SIZE=0x1000
)

# --- Hardware / SDK libs ---
target_link_libraries(fjaeger PRIVATE
  pico_stdlib
  pico_unique_id
  pico_rand
  pico_sha256
  hardware_sha256
  pico_mbedtls
  pico_mbedtls_crypto
  hardware_flash
  hardware_timer
  hardware_pio
  hardware_watchdog
  pico_bootrom
  pico_binary_info
  pico_bit_ops
  pico_divider
  pico_mem_ops
  pico_platform
  pico_sync
  pico_time
  pico_util
  tinyusb_board
  tinyusb_device
)

pico_generate_pio_header(fjaeger
  ${CMAKE_CURRENT_SOURCE_DIR}/src/led/rgb_led.pio
)

# I/O: UART for debug, USB for the app console
pico_enable_stdio_uart(fjaeger 1)
pico_enable_stdio_usb(fjaeger 0)
pico_add_extra_outputs(fjaeger)

target_compile_options(fjaeger PRIVATE -Wall -Wextra)
