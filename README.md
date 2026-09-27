# Fjaeger

Sikkerhetsnøkkel (USB-dongle) bygget på **RP2350** (16 MB flash). Prosjektet gir en kombinasjon av en FIDO2-autentikator for SSH, og en liten kryptert USB-stasjon, styrt over et serial-kommandogrensesnitt.

## Funksjoner

- **CTAP2 (FIDO2) over HID** — `authenticatorGetInfo`, `makeCredential` og `getAssertion` med CBOR, for WebAuthn og OpenSSH `sk-ecdsa`-nøkler. Attestasjon bruker formatet `none`.
- **Profiler** — opptil 8 navngitte profiler. Hver profil er et tilgangsfilter over CTAP2-credentials: bare credentials i valgt profil kan oppdages eller brukes, og nye credentials knyttes automatisk til valgt profil. Velg profil over serial med `PROFILE SELECT <id>`.
- **Kryptert USB-stasjon (MSC)** — en **12 MiB vedvarende** FAT16-partisjon i on-board-flash, AES-XTS-kryptert med en **dedikert disknøkkel** som er uavhengig av profiler. Mountes bare når enheten er ulåst. Data overlever reboot.
- **Lås/ulås-modell** — når låst nektes signering, avkryptering og skriving. Ulåsing krever PIN over serial.
- **Brute-force-beskyttelse** — enhets-PIN og disk-PIN sperres etter fem feil. En felles recovery-PUK kan fjerne sperren; fem feil PUK-forsøk utfører factory-wipe.
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
│   ├── keys.h/.c           Profiler og lagring i flash, aktiv profil
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
- **Enhetslås** (`LOCK`/`UNLOCK`): når låst er det ingen ECDSA-signering. Låses opp med PIN over serial.
- **Disk-lås** (`DISK LOCK`/`DISK UNLOCK`): den krypterte MSC-en er kun mountet/lesbar/skrivbar når `DISK UNLOCK` er gitt. `DISK UNLOCK` krever at enheten er ulåst; `LOCK` og auto-relåsing lukker også disken.
- MSC-disken bruker en **dedikert permanent XTS-nøkkel** lagret i flash-lageret, uavhengig av profiler. Bytte eller sletting av profiler endrer ikke diskdata.
- PIN-en lagres foreløpig som en SHA-256-hash og sammenlignes i konstant tid. Dette er ikke tilstrekkelig beskyttelse mot offline-angrep på en flashdump og skal erstattes med saltet, treg nøkkelavledning.
- Enhets-PIN og disk-PIN har separate, vedvarende feiltellere. PUK fjerner en disk-PIN-sperre, men erstatter ikke disk-PIN: disknøkkelen er fortsatt pakket med den riktige disk-PIN-en.

> **Merk:** RP2350 har ingen ekte hardware secure element (som ATECC608B). Secure boot finnes, men beskyttelse mot en fysisk angriper med laboratorieutstyr er begrenset. Dette er en prototype/utviklingsplattform, ikke sertifisert produksjonssikkerhetsnøkkel.

## Bygge

Forutsetninger: CMake ≥ 3.13, ARM-none-EABI-toolchain, **Pico SDK ≥ 2.1.0** (helst 2.2.0) og **`picotool`** på PATH (for flashing). Hosttestene trenger bare `cc` (x86-64).

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

Resultat: `build/fjaeger.uf2`. Sett donglen i BOOTSEL-modus og flash med et av
skriptene:

```bash
scripts/reflash.sh            # bare firmware; disk + lager (profiler/PIN) bevares
scripts/reflash_wipe.sh       # sletter hele flash (firmware + disk + lager), så flasher
```

`reflash.sh` skriver kun firmwaren og bevarer MSC-disken og lageret
(profiler, PIN, PUK, CTAP2-credentials). `reflash_wipe.sh` sletter hele
16 MB flash først (fabrikksletting på flash-nivå) og krever bekreftelse
(`YES`); ved neste oppstart opprettes en tom «Default»-profil.

**Flash-layout:** firmware ~128 KB fra `0x10000000`, disk-partisjon 12 MiB fra
`0x10100000`, lager (PIN/profiler/CTAP2/disknøkkel) i de siste 8 KiB. En vanlig
firmware-flash rører verken disken eller lageret; bare en full erase sletter
dem.

## Serial-kommandoer

Koble til konsollen (f.eks. `screen /dev/ttyACM0 115200`):

| Kommando | Beskrivelse |
|----------|-------------|
| `HELP` | Liste kommandoer |
| `STATUS` | Vis enhet + disk-tilstand, aktiv profil, profiler, timeout |
| `LOCK` | Lås enheten (og lukk disken) |
| `UNLOCK <pin>` | Lås opp **enheten** for nøkkeloperasjoner (ikke disken) |
| `SETPIN <pin>` | Sett/endre PIN |
| `UNLOCKPUK <puk>` | Lås opp sperret enhets-PIN med recovery-PUK |
| `PUK <code>` | Sett/endre recovery-PUK |
| `DISK SETPIN <pin>` | Sett/endre disk-PIN |
| `DISK UNLOCK <pin>` | Lås opp/mount den krypterte disken (eget steg) |
| `DISK UNBLOCK <puk>` | Fjern disk-PIN-sperre; korrekt disk-PIN kreves etterpå |
| `DISK LOCK` | Lås/unmount disken |
| `DISK STATUS` | Vis disk-tilstand |
| `PROFILE LIST` | Vis alle profiler, aktiv markering og credential-antall |
| `PROFILE CREATE <id> <name>` | Opprett en ny tom profil |
| `PROFILE SELECT <id>` | Velg og lagre aktiv profil |
| `PROFILE RENAME <id> <name>` | Endre navn uten å endre credentials |
| `PROFILE ERASE <id>` | Slett profilen og alle dens credentials |
| `TIMEOUT <seconds>` | Lagre auto-relåsing (standard 900 sekunder; 0 = av) |
| `RESET` | Tilbakestill enheten |

> **Uavhengig disk-lås:** `UNLOCK <pin>` låser bare opp **enheten** (for FIDO/SSH-signering). Den krypterte disken er et separat steg: `DISK UNLOCK`. `LOCK` og auto-relåsing lukker også disken, og `DISK UNLOCK` krever at enheten er ulåst.

Auto-lock er 15 minutter som fabrikkstandard. `TIMEOUT`-verdien lagres i
flashlageret og overlever både omstart og vanlig firmwareflash. `TIMEOUT 0`
lagres som en eksplisitt deaktivering.

Konsollen ekkoer ikke kommandoer. Slå også av lokal echo i terminalprogrammet;
fastvaren nullstiller kommandobufferen etter hver kommando, men kan ikke slette
tekst som terminalprogrammet selv har vist eller logget.

## SSH (sk-nøkler)

Donglen er en CTAP2-autentikator med ECDSA P-256-nøkler, så den brukes med
**`sk-ecdsa-sha2-nistp256@openssh.com`** — **ikke** `ed25519-sk` (enheten har
ingen EdDSA-nøkkel). Enheten må være **ulåst** (PIN over serial) og **riktig
profil valgt** før credential-operasjoner slipper gjennom.

### Hvordan en nøkkel lages (enroll)

```bash
# 1. Lås opp donglen og velg profil over konsollen:
#    UNLOCK <pin>  og  PROFILE SELECT <id>
# 2. Finn FIDO-enheten (f.eks. /dev/hidraw2) og generer nøkkelen:
ssh-keygen -t ecdsa-sk -O device=/dev/hidraw2 \
  -f ~/.ssh/id_ecdsa_sk -N '' -C fjaeger-test
```

`ssh-keygen` sender `makeCredential` (CTAP2) til donglen, som:
1. genererer en **tilfeldig P-256-privatnøkkel** som **aldri forlater enheten**;
2. lagrer den i flash med `credential_id` og `rp_id_hash` (SHA-256 av RP-en,
   her `ssh:`), **bundet til aktiv profil**;
3. returnerer kun `credential_id` + offentlig nøkkel til PC-en.

Resultatet er `~/.ssh/id_ecdsa_sk` (inneholder credential-ID + offentlig nøkkel)
og `~/.ssh/id_ecdsa_sk.pub`. Legg `.pub` i vertens `authorized_keys`.

### Hvordan en nøkkel virker (signering)

Ved innlogging sender OpenSSH `getAssertion` med credential-ID-en i allowList.
Donglen:
1. **verifiserer at credentialet er i aktiv profil** — er feil profil valgt
   nektes signering, selv om PC-en har riktig nøkkelfil;
2. signerer `authData || clientDataHash` med den lagrede private nøkkelen;
3. returnerer DER-signaturen til PC-en, som sender den til verten.

```bash
ssh -i ~/.ssh/id_ecdsa_sk -o ControlPath=none bruker@vert
```

Bruk `-o ControlPath=none` under testing — `ControlMaster`/multiplexing i
`~/.ssh/config` kan gjenbruke en eksisterende forbindelse uten ny
autentisering og dermed maskere profilisoleringen.

### Verifisere en signatur uten SSH-innlogging

```bash
ssh-keygen -Y sign -f id_ecdsa_sk -n test fil.txt      # lager fil.txt.sig
ssh-keygen -Y verify -f allowed_signers -I <navn> -n test -s fil.txt.sig < fil.txt
```

`allowed_signers` må ha formen `navn sk-ecdsa-sha2-nistp256@openssh.com <base64 nøkkel>`.

### Nøkkelmodellen

- **Privatnøkkelen ligger bare i donglen**, aldri på PC-en. PC-en har kun
  credential-ID + offentlig nøkkel.
- **Profilen er tilgangsfilteret**: donglen nekter å bruke credentials utenfor
  aktiv profil. SSH-filen kan peke på samme credential-ID, men virker bare når
  riktig profil er valgt.
- En profil er **ikke** en felles nøkkel — hvert credential har sin egen
  tilfeldige P-256-nøkkel.
- CTAP2-credentials lagres i flash (opptil 8) i et kontrollsummert A/B-format.
  Attestasjonen er `none`. Slettet profil → credentials ubrukelige;
  factory-wipe (5 feil PUK) sletter alle profiler og credentials.

## Status / kjent begrensning

- **Legacy U2F/CTAP1 er deaktivert.** Enheten annonserer CTAPHID `NMSG` inntil CTAP1-koden eventuelt erstattes med en komplett implementasjon.
- **CTAP2** har implementasjoner av `authenticatorGetInfo`, `makeCredential` og `getAssertion` med `none`-attestasjon. Parser og responsformat har hosttester; OpenSSH enrollment, signering, verifisering og reell SSH-innlogging er fysisk testet på RP2350-donglen.
  - Kun **ECDSA P-256 / ES256** støttes (ingen EdDSA/ed25519-sk).
  - Enheten må være ulåst (PIN) for at `makeCredential`/`getAssertion` skal aksepteres.
  - Credentials er flash-persistente (opptil 8) i et kontrollsummert A/B-format, skrevet deferert fra main-loop.
- MSC-disken er en **12 MiB vedvarende FAT16-partisjon** i on-board-flash, AES-XTS-kryptert i farten med en **dedikert disknøkkel** (uavhengig av profiler). Metadata (boot, FAT, rot) initialiseres én gang ved første oppstart; dataregionen skrives lazy. Data overlever reboot.
  - **Deferred write-behind:** USB MSC-callbacker køer sektor-skriver; selve flash-erase/program gjøres i main-loop (`fj_msc_task`), aldri inne i en USB-transaksjon. Data flusher ved `LOCK`/unmount og kontinuerlig.
  - **Integritet:** en vedvarende CRC-32-tabell (én per 4 KiB-blokk, lagret i klartekst i de siste blokkene av partisjonen) verifiseres ved mount. Korrupsjon fra strømbrudd eller tukling oppdages og disken re-initialiseres i stedet for å serve korrupte data.
  - Skriving av store filer er treg og sliter på flash fordi hver sektoroppdatering krever flash-erase.

## Lisens

BSD-3-Clause.
