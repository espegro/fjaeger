# Fjaeger — Prosjektstatus

Oppdatert: 2026-09-26

## Audit og reparasjon påbegynt

Et lokalt Git-repository ble opprettet med baseline-commit `3c2ad51`. Første
stabiliseringscommit retter følgende:

- Konsolltokenisering for kommandoer med argumenter.
- ECDSA-signering med gyldig blinding-RNG og validerte P-256-privatnøkler.
- Kontrollsummert A/B-nøkkellager med 256-byte-justerte flashskrivinger.
- CTAPHID INIT, kommandoverdier og asynkron utsending av flerpakke-svar.
- Sentrale CTAP2/CBOR-feil, DER-signatur og riktig signaturgrunnlag.
- MSC-tilgang stenges nå også ved auto-lock; FAT12-grunnbildet er reparert.
- WS2812/SK6812-kompatibel RGB-status-LED på GPIO22 via PIO, med blått
  aktivitetspuls for konsoll, FIDO og disk-I/O.
- Hosttest for `GetInfo` → `MakeCredential` → `GetAssertion`.

Legacy U2F/CTAP1 annonseres ikke lenger; den gamle MSG-koden er deaktivert. Fysisk
test med `libfido2` og OpenSSH gjenstår før CTAP2 kan regnes som verifisert.

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
- **U2F (CTAP1)** — deaktivert inntil den kan implementeres protokollkorrekt.
- **Nøkkelprofiler ("slots")** — opptil 8, hver med ECDSA P-256 + XTS-nøkkel,
  persistente i flash.
- **Kryptert USB-stasjon (MSC-prototype)** — AES-XTS, mountes kun når ulåst;
  backing store er ennå bare 8 KiB RAM.
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
│   ├── u2f.h/.c            CTAPHID-transport; legacy MSG er deaktivert
│   ├── ctap2.h/.c          CTAP2-kommandoer (CBOR)
│   └── cbor.h/.c           Minimal CBOR-encoder/decoder
├── led/
│   ├── rgb_led.h/.c        RGB-status-LED på GPIO22
│   └── rgb_led.pio         WS2812/SK6812-driver
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
- Konsollen er fysisk testet med `HELP`, `STATUS`, `LOCK`, riktig og feil
  `UNLOCK`, `SETPIN`, `KEY LIST`, `KEY SELECT`, `KEY PROVISION`, `KEY ERASE`,
  `TIMEOUT`, ugyldige argumenter og `RESET`.
- Auto-lock er fysisk verifisert med to sekunders timeout.
- PIN og slotdata overlever firmwareflash og watchdog-reset.
- MSC-prototypen enumererer og mountes som et 8 KiB FAT-volum når ulåst, og
  mountpunktet forsvinner ved låsing.
- Hosttesten dekker CTAP2 `GetInfo` → `MakeCredential` → `GetAssertion`.

## Kjente problemer / åpne punkter

1. **`SETPIN` og `UNLOCK` må testes på fysisk enhet.** Parserfeilen er rettet og
   `<strings.h>` er inkludert.
2. **PIN vises i klartekst** når den settes/låses opp via konsoll (`SETPIN <pin>`, `UNLOCK <pin>`).
   - Status: ikke adressert.
3. **Foreldet attestasjonskode er slettet.** CTAP2 bruker `none`.
4. **SSH / `ssh-keygen -t ecdsa-sk`** er ikke testet end-to-end ennå.
   - Enheten må være ulåst (PIN) før `makeCredential`/`getAssertion` aksepteres.
   - Kun ECDSA P-256 / ES256 støttes (ingen ed25519-sk).
5. MSC er fortsatt en RAM-disk (8 KB), ikke vedvarende i flash. XTS gir heller
   ikke autentisering/integritetsbeskyttelse.

## Anbefalte neste steg

1. Flashe og teste konsoll, LED og låsing på fysisk dongle.
2. Verifisere CTAPHID med `fido2-token` og deretter `ssh-keygen -t ecdsa-sk`.
3. Erstatte rå SHA-256 av PIN med saltet, treg nøkkelavledning og legge inn
   forsinkelse etter feil PIN.
4. Lage en eksplisitt flashpartisjon og persistent backing store for MSC.
5. Lage sikker PIN-inntasting uten synlig PIN i kommandolinjen.
