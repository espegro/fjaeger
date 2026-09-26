# Fjaeger — Prosjektstatus

Oppdatert: 2026-09-26

## Overblikk

Fjaeger er en USB-sikkerhetsnøkkel (dongle) bygget på RP2350. Prosjektet kombinerer en
FIDO/CTAP2-autentikator (for SSH / WebAuthn) med en liten kryptert USB-stasjon (MSC),
styrt over et seriell-kommandogrensesnitt (USB CDC).

Donglen er en **TENSTAR RP2350-USB 16 MB**.

## Verktøy / SDK

| Komponent | Verdi |
|-----------|-------|
| Pico SDK | **2.2.0** (`/home/espegro/programming/pico-sdk`) |
| Board-profil | **`waveshare_rp2350_plus_16mb`** (elektrisk kompatibel med TENSTAR RP2350-USB 16MB) |
| Toolchain | ARM-none-EABI GCC 14.2.1 |
| mbedTLS | 3.x (via SDK 2.2.0) |
| TinyUSB | via SDK 2.2.0 (RP2350-USB-støtte) |
| Flash | 16 MB |

> Viktig: Dette bygget krever Pico SDK ≥ 2.1.0 (helst 2.2.0) med `waveshare_rp2350_plus_16mb`-board.
> Tidligere brukt Pico SDK 2.0.0 + `pico2`-profilen ga ingen USB-enumerering (TinyUSB 0.16.0 manglet RP2350-støtte).

## Bygge

```bash
cmake -S . -B build \
  -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

Resultat: `build/fjaeger.uf2` (flash via bootrom BOOTSEL).

## Funksjoner

- **CTAP2 (FIDO2) over HID** — `authenticatorGetInfo` (0x04), `makeCredential` (0x01),
  `getAssertion` (0x02), `authenticatorCancel` (0x06). Attestasjon-format **`none`**.
- **U2F (CTAP1) over HID** — U2FHID-transport, `U2F_AUTHENTICATE`, `U2F_REGISTER`
  (uten X.509-attestasjon).
- **Nøkkelprofiler ("slots")** — opptil 8, hver med ECDSA P-256 + AES-256-nøkkel,
  persistente i flash.
- **Kryptert USB-stasjon (MSC)** — AES-256-XTS, mountes kun når ulåst.
- **Lås/ulås-modell** — PIN over serial, auto-relåsing.
- **Seriell-konsoll (USB CDC)** — kommandoer for tilstand og nøkkelhåndtering.

## Arkitektur

```
src/
├── main.c                  Inngangspunkt, init, main-loop
├── core/
│   ├── state.h/.c          Tilstandsmaskin (LOCKED/UNLOCKED), PIN, auto-relock
│   ├── keys.h/.c           Nøkkelprofiler/slots + CTAP2-creds i flash, aktiv slot
│   ├── crypto.h/.c         mbedTLS-innpakninger: ECDSA, SHA-256, HKDF, AES-XTS
│   └── ms_time.c           mbedTLS 3.x tidssource (mbedtls_ms_time)
├── fido/
│   ├── u2f.h/.c            U2FHID-transport + U2F_AUTHENTICATE/REGISTER
│   ├── ctap2.h/.c          CTAP2-kommandoer (CBOR)
│   ├── cbor.h/.c           Minimal CBOR-encoder/decoder
│   └── attestation.h/.c    UTDATERINGSTREVET: fjernet fra bygget (ubrukt)
├── usb/
│   ├── tusb_config.h       TinyUSB-konfig (CDC + HID + MSC)
│   ├── usb_descriptors.c   Composite-descriptorer
│   ├── msc_disk.c/.h       Kryptert MSC-disk
│   └── cdc_console.c/.h    Seriell-kommandogrensesnitt
└── mbedtls_config/
    └── fjaeger_mbedtls_config.h  mbedTLS 3.x config (wrapper over default)
```

## Hva som er fikset under debug-sesjonen

1. **USB-enumerering:** Byttet fra Pico SDK 2.0.0 + `pico2` → SDK 2.2.0 + `waveshare_rp2350_plus_16mb`.
   - Rettet `CFG_TUSB_MCU` (var udefinert i CMake-bygget).
   - Rettet endepunktskonflikt (HID IN `0x81` kolliderte med CDC-notif `0x81`).
   - Rettet device-class til per-interface (`0x00`).
2. **mbedTLS 3.x-migrering:** Ny config-wrapper (`fjaeger_mbedtls_config.h`) over default-config,
   med Pico-spesifikke makroer (`MBEDTLS_NO_PLATFORM_ENTROPY`, `MBEDTLS_ENTROPY_HARDWARE_ALT`,
   `MBEDTLS_SHA256_ALT`, `MBEDTLS_PLATFORM_MS_TIME_ALT`).
   - Deaktiverte moduler som ikke virker på Pico: TLS/SSL, X.509, `MBEDTLS_TIMING_C`,
     `MBEDTLS_NET_C`, `MBEDTLS_SHA3_C`.
   - Ny `src/core/ms_time.c` som leverer `mbedtls_ms_time()`.
3. **X.509-attestasjon fjernet:** `attestation.c` fjernet fra bygget (CTAP2 bruker `none`).
4. **Init-kræsj fikset:** `fj_console_init()` kalte `tud_task()` (via `outln()`) **før**
   `tud_init()`, noe som kræsjet fastvaren. Banner-utskriften fjernet fra `fj_console_init()`.

## Verifisert

- Fastvaren bygger grønt (`EXIT=0`), `build/fjaeger.uf2` produseres.
- USB enummererer: `2e8a:4007 Fjaeger Fjaeger Security Key` (`/dev/ttyACM0`).
- Konsollen svarer på `HELP`.

## Kjente problemer / åpne punkter

1. **`SETPIN` og `UNLOCK` virker ikke** — `SETPIN 1234` gir `ERR unknown command`.
   - Mistenkt: `cdc_console.c` bruker `strcasecmp()` uten `#include <strings.h>`.
   - Status: ikke fikset ennå.
2. **PIN vises i klartekst** når den settes/låses opp via konsoll (`SETPIN <pin>`, `UNLOCK <pin>`).
   - Status: ikke adressert.
3. **`attestation.c/.h` er foreldet** — ligger igjen i `src/fido/`, men er fjernet fra bygget.
   Bør slettes.
4. **SSH / `ssh-keygen -t ecdsa-sk`** er ikke testet end-to-end ennå.
   - Enheten må være ulåst (PIN) før `makeCredential`/`getAssertion` aksepteres.
   - Kun ECDSA P-256 / ES256 støttes (ingen ed25519-sk).
5. MSC er en RAM-disk (8 KB), ikke vedvarende i flash.

## Anbefalte neste steg

1. Fikse `SETPIN`/`UNLOCK` (legge til `#include <strings.h>`), bygge, flashe og teste.
2. Vurdere sikkerere PIN-inntasting (skjule ekko / unngå klartekst i kommandolinje).
3. Slette foreldede `attestation.c/.h`.
4. Verifisere `ssh-keygen -t ecdsa-sk` end-to-end.