# Fjaeger

Sikkerhetsnøkkel (USB-dongle) bygget på **RP2350** (16 MB flash). Prosjektet gir en kombinasjon av en FIDO2-autentikator for SSH, og en liten kryptert USB-stasjon, styrt over et serial-kommandogrensesnitt.

## Funksjoner

- **CTAP2 (FIDO2) over HID** — `authenticatorGetInfo`, `makeCredential` og `getAssertion` med CBOR, for WebAuthn og OpenSSH `sk-ecdsa`-nøkler. Attestasjon bruker formatet `none`.
- **Flere nøkkelprofiler ("slots")** — opptil 8 uavhengige profiler, hver med egen ECDSA-nøkkel og XTS-nøkkel. Velg aktiv profil over serial med `KEY SELECT <n>`.
- **Kryptert USB-stasjon (MSC, prototype)** — XTS-krypterte sektorer. Enheten mountes bare når den er ulåst, men backing store er foreløpig kun 8 KiB RAM.
- **Lås/ulås-modell** — når låst nektes signering, avkryptering og skriving. Ulåsing krever PIN over serial.
- **Serial-konsoll (USB CDC)** — `LOCK`, `UNLOCK`, `RESET`, `TIMEOUT`, nøkkelhåndtering, m.m.

## Hardware

- Raspberry Pi RP2350 (16 MB flash, `waveshare_rp2350_plus_16mb`-brettprofil)
- Integrert USB-A-plugg
- Adressebar RGB-LED på GPIO22: rød = låst, grønn = ulåst, gul = ikke enumerert, blå puls = USB-aktivitet

## Arkitektur

```
src/
├── main.c                  Inngangspunkt, init, main-loop
├── core/
│   ├── state.h/.c          Tilstandsmaskin (LOCKED/UNLOCKED), PIN, auto-relock
│   ├── keys.h/.c           Nøkkelprofiler/slots i flash, aktiv slot
│   └── crypto.h/.c         mbedTLS-innpakninger: ECDSA, SHA-256, HKDF, AES-XTS
├── fido/
│   ├── u2f.h/.c            CTAPHID-transport (legacy CTAP1/MSG deaktivert)
│   ├── ctap2.h/.c          CTAP2-kommandoer (makeCredential/getAssertion/GetInfo)
│   └── cbor.h/.c           Minimal CBOR-encoder/decoder
├── led/
│   ├── rgb_led.c/.h        Tilstands-LED på GPIO22
│   └── rgb_led.pio         WS2812/SK6812 PIO-program
└── usb/
    ├── tusb_config.h       TinyUSB-konfig (CDC + HID + MSC)
    ├── usb_descriptors.c   Composite-descriptorer
    ├── msc_disk.c/.h       Kryptert MSC-disk
    └── cdc_console.c/.h    Serial-kommandogrensesnitt
```

### Sikkerhetsmodell

- Private nøkler lagres i RP2350-flash og brukes kun for signering i fastvaren; de eksporteres aldri over serial.
- Når enheten er **låst**: ingen ECDSA-signering, og MSC-en er ikke klar, lesbar eller skrivbar.
- Når **ulåst**: PIN er verifisert, MSC-en er mountet og dekrypterer sektorer i farten.
- PIN-en lagres foreløpig som en SHA-256-hash og sammenlignes i konstant tid. Dette er ikke tilstrekkelig beskyttelse mot offline-angrep på en flashdump og skal erstattes med saltet, treg nøkkelavledning.

> **Merk:** RP2350 har ingen ekte hardware secure element (som ATECC608B). Secure boot finnes, men beskyttelse mot en fysisk angriper med laboratorieutstyr er begrenset. Dette er en prototype/utviklingsplattform, ikke sertifisert produksjonssikkerhetsnøkkel.

## Bygge

Forutsetninger: CMake ≥ 3.13, ARM-none-EABI-toolchain, **Pico SDK ≥ 2.1.0** (helst 2.2.0).

Donglen er en **TENSTAR RP2350-USB 16 MB** og bruker board-profilen
`waveshare_rp2350_plus_16mb` (elektrisk kompatibel). Den bygges mot Pico SDK
2.2.0 (med TinyUSB som støtter RP2350).

```bash
# Bruk SDK 2.2.0 (trengs for RP2350-USB-støtte)
cmake -S . -B build \
  -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

Resultat: `build/fjaeger.uf2` (flash via bootrom BOOTSEL).

## Serial-kommandoer

Koble til konsollen (f.eks. `screen /dev/ttyACM0 115200`):

| Kommando | Beskrivelse |
|----------|-------------|
| `HELP` | Liste kommandoer |
| `STATUS` | Vis tilstand, aktiv slot, antall slots, timeout |
| `LOCK` | Lås enheten umiddelbart |
| `UNLOCK <pin>` | Lås opp med PIN |
| `SETPIN <pin>` | Sett/endre PIN |
| `KEY LIST` | Vis alle slots |
| `KEY SELECT <n>` | Velg aktiv profil |
| `KEY PROVISION <n> [name]` | Opprett ny nøkkel i slot `n` |
| `KEY ERASE <n>` | Slett slot `n` |
| `TIMEOUT <seconds>` | Sett auto-relåsing (0 = av) |
| `RESET` | Tilbakestill enheten |

## SSH (sk-nøkler)

Donglen er en CTAP2-autentikator med en ECDSA P-256-nøkkel, så den brukes med **`sk-ecdsa-sha2-nistp256@openssh.com`** — **ikke** `ed25519-sk` (enheten har ingen EdDSA-nøkkel). Enheten må være **ulåst** (PIN over serial) før credential-operasjoner slipper gjennom.

```bash
# Generer et par (non-resident; credentialet lagres i donglens flash)
ssh-keygen -t ecdsa-sk -f ~/.ssh/id_ecdsa_sk

# Legg til på verten og bruk som vanlig
ssh-add ~/.ssh/id_ecdsa_sk
```

CTAP2-credentials lagres i donglens flash (opptil 8). Attestasjonen er `none`, som OpenSSH og de fleste WebAuthn-tjenester godtar.

## Status / kjent begrensning

- **Legacy U2F/CTAP1 er deaktivert.** Enheten annonserer CTAPHID `NMSG` inntil CTAP1-koden eventuelt erstattes med en komplett implementasjon.
- **CTAP2** har implementasjoner av `authenticatorGetInfo`, `makeCredential` og `getAssertion` med `none`-attestasjon. Parser og responsformat har hosttester, men fysisk end-to-end-test med OpenSSH gjenstår.
  - Kun **ECDSA P-256 / ES256** støttes (ingen EdDSA/ed25519-sk).
  - Enheten må være ulåst (PIN) for at `makeCredential`/`getAssertion` skal aksepteres.
  - Credentials er flash-persistente (opptil 8) i et kontrollsummert A/B-format, skrevet deferert fra main-loop.
- MSC-disken er en liten RAM-disk (8 KB) som grunnlag; den er kryptert i farten, men ikke vedvarende i flash.

## Lisens

BSD-3-Clause.
