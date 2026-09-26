# Fjaeger — status og overlevering

Oppdatert: 2026-09-27 (dedikert disk-PIN, PUK og brute-force-beskyttelse)

## Kort status

Fjaeger kjører nå som en sammensatt USB-enhet på en **TENSTAR RP2350-USB med
16 MB flash**:

- USB CDC-konsoll for PIN, låsing og nøkkelprofiler.
- CTAP2/FIDO2 over HID for OpenSSH `sk-ecdsa`.
- Kryptert MSC-prototype som bare er tilgjengelig når enheten er ulåst.
- Adressebar RGB-status-LED på GPIO22.

OpenSSH-registrering, signering og lokal signaturverifisering er fysisk testet
og virker. En låst dongle nekter signering. Siste verifiserte commit er
`5f1ac23` (`Fix CTAP2 OpenSSH enrollment and signing`).

Donglen ble etter siste test etterlatt **låst**. Test-PIN er **`12345`**. Dette
er bare et utviklingsoppsett og må endres før reell bruk.

## Byggemiljø

| Komponent | Verdi |
|---|---|
| Pico SDK | 2.2.0 (`/home/espegro/programming/pico-sdk`) |
| Board | `waveshare_rp2350_plus_16mb` |
| Toolchain | ARM-none-EABI GCC 14.2.1 |
| mbedTLS | 3.x fra Pico SDK |
| USB | TinyUSB fra Pico SDK 2.2.0 |
| Flash | 16 MB |

`waveshare_rp2350_plus_16mb` brukes fordi den er elektrisk kompatibel med
TENSTAR-kortet. Pico SDK 2.0.0 med `pico2` ga tidligere ingen fungerende
USB-enumerering.

Bygg:

```bash
cmake -S . -B build \
  -DPICO_SDK_PATH=/home/espegro/programming/pico-sdk \
  -DPICO_BOARD=waveshare_rp2350_plus_16mb
cmake --build build -j$(nproc)
```

UF2-filen blir `build/fjaeger.uf2` og flashes i BOOTSEL-modus, for eksempel:

```bash
picotool load -f build/fjaeger.uf2
picotool reboot
```

Hosttesten kjøres slik:

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Isrc/core -Isrc/fido \
  tests/test_ctap2.c src/fido/ctap2.c src/fido/cbor.c \
  -o /tmp/fjaeger-test-ctap2
/tmp/fjaeger-test-ctap2
```

Forventet resultat: `ctap2 host tests: ok`.

Sikkerhetstilstandstesten kjøres slik:

```bash
cc -std=c11 -Wall -Wextra -Werror \
  -Itests/stubs -Isrc/core -Isrc/fido -Isrc/usb \
  tests/test_security.c src/core/state.c \
  -o /tmp/fjaeger-test-security
/tmp/fjaeger-test-security
```

Forventet resultat: `security host tests: ok`. Den dekker PIN-sperring,
PUK-gjenåpning, full live factory-wipe og at auto-lock også lukker disken.

## Fikset i denne runden

### Grunnleggende firmware og USB

- Rettet USB-enumerering ved å bruke riktig SDK og board-profil.
- Rettet TinyUSB MCU-konfigurasjon, device class og kolliderende endepunkter.
- Fjernet konsollutskrift før `tud_init()`, som tidligere krasjet under oppstart.
- Tilpasset mbedTLS 3.x til RP2350 og fjernet ubrukte TLS/X.509-moduler.
- Fjernet gammel X.509-attestasjon; CTAP2 bruker `fmt: none`.

### Konsoll, låsing og flash

- Rettet tokenisering av kommandoer med argumenter.
- Rettet PIN- og slotlagring til et kontrollsummert A/B-lager i de to siste
  flashsektorene.
- Flashprogrammering er justert til 256-byte-sider.
- PIN, slots og CTAP2-credentials overlever reset og vanlig firmwareflash.
- Auto-lock kobler også bort MSC-tilgang.
- Auto-lock er 900 sekunder som standard. `TIMEOUT <sekunder>` lagres i
  A/B-flashlageret og overlever omstart; `TIMEOUT 0` deaktiverer den vedvarende.
- Enhets-PIN og disk-PIN sperres separat etter fem feilforsøk. Recovery-PUK
  nullstiller sperren; fem feil PUK-forsøk låser alt, nullstiller live
  nøkkelmateriale og sletter begge kopier av flashlageret.
- `DISK UNBLOCK <puk>` fjerner bare disk-PIN-sperren. PUK kan ikke erstatte
  disk-PIN eller dekryptere disknøkkelen.
- Konsollen ekkoer ikke hemmeligheter og nullstiller kommandobufferen etter
  behandling. Lokal echo/logging må deaktiveres i terminalprogrammet.

### FIDO/CTAP2 og OpenSSH

- Rettet CTAPHID INIT, kommandoverdier, flerpakke-svar og transportbufferens
  levetid.
- Rettet utvidet APDU-lengde og lagt inn en minimal CTAP1 REGISTER-probe som
  libfido2/OpenSSH kan bruke ved tokenvalg. Dette er **ikke full U2F/CTAP1**.
- Rettet kanonisk CBOR-rekkefølge i `GetInfo` og `GetAssertion`.
- Rettet `makeCredential`, `getAssertion`, authData, DER-signatur og korrekt
  signaturgrunnlag.
- Flyttet store CTAP-/kryptobuffere ut av stacken og økte tilgjengelig stack.
- Rettet P-256 public-key-beregning ved å gi mbedTLS en blinding-RNG.
- Rettet heng under signering. Det ble isolert til deterministisk ECDSA via
  HMAC-DRBG; sannsynlig årsak er samspillet med Pico-SDK-ens globalt låste
  SHA-256-maskinvarekontekst. Signering bruker nå RP2350-maskinvare-RNG for både
  engangsskalar og blinding, og fysisk signering fullfører.
- Lagt inn eksplisitt validering av lagret privat P-256-nøkkel før signering.

### MSC og LED

- Reparert FAT12-grunnbildet for MSC-prototypen.
- MSC rapporterer utilgjengelig når donglen er låst eller auto-lock slår inn.
- Implementert WS2812/SK6812-kompatibel LED-driver via PIO på GPIO22:
  - rød: låst
  - grønn: ulåst
  - gul: ikke USB-enumerert
  - kort blå puls: konsoll-, FIDO- eller diskaktivitet

## Fysisk verifisert

Følgende er testet på den faktiske RP2350-donglen:

- Firmware bygger, flashes og starter.
- USB enumererer som CDC + FIDO HID + MSC.
- `/dev/ttyACM0` og FIDO `hidraw`-enhet opprettes.
- Konsollkommandoene `HELP`, `STATUS`, `LOCK`, `UNLOCK`, `SETPIN`, `KEY LIST`,
  `KEY SELECT`, `KEY PROVISION`, `KEY ERASE`, `TIMEOUT` og `RESET` er prøvd,
  inkludert feil PIN og ugyldige argumenter.
- Auto-lock med to sekunders timeout er prøvd.
- PIN og slotdata har overlevd firmwareflash og watchdog-reset.
- MSC mountes som et 8 KiB FAT-volum når ulåst og forsvinner ved låsing.
- LED-status og aktivitetspuls er observert under tidligere fysisk test.
- OpenSSH `ecdsa-sk` credential er opprettet via CTAP2.
- Credential har overlevd firmwareflash og kan finnes igjen via credential-ID.
- `ssh-keygen -Y sign` fullfører mot donglen uten heng.
- Signaturen består `ssh-keygen -Y verify` med den registrerte public key.
- Etter `LOCK` blir samme signeringsforsøk avvist.

Verifisert testnøkkel hadde fingeravtrykk:

```text
SHA256:9/nEEvU6esvFLkLMgzOCgwF4HcjF0immAN8MU4s5qq0
```

## Fysisk verifisert 2026-09-26 (neste runde)

Følgende er nå også verifisert på den faktiske donglen:

- **Reell SSH-innlogging.** `ecdsa-sk`-nøkkelen i `authorized_keys` logger inn
  mot en lokal `sshd` på port 22022 (`SSH_LOGIN_OK`). Tidligere var bare
  `ssh-keygen` enroll/sign/verify prøvd.
- **Kaldstart og utholdenhet.** Etter ekte strømfrakobling starter enheten
  **låst**, PIN `12345` overlever og låser opp, og credential i slot 0 overlever
  og kan logge inn igjen via SSH. Gjaldt også over watchdog-`RESET`.
- **Flere credentials.** Åtte distinkte `sk-ecdsa`-credentials ble opprettet;
  hver autentiserer uavhengig mot `sshd`. Niende forsøk avvises
  (`CTAP2_ERR_NOT_ALLOWED`, `ssh-keygen` melder `Key enrollment failed:
  invalid format`, RC=255). Hele lageret overlever reset.
- **Uavhengig FIDO2-klient.** `python3-fido2` (libfido2-uavhengig) enumererer,
  henter `GetInfo` (FIDO_2_0), utfører `getAssertion`-signering mot en
  eksisterende credential (gyldig DER-signatur, korrekt rpIdHash) og avviser
  `makeCredential` med fullt lager. OpenSSH/libfido2 og python3-fido2 begge
  fungerer.
- **Konsollregresjon.** Hele kommandolisten kjørt igjen: 42/42 sjekker bestått,
  inkludert feiltilfeller, grenselengder, slot 0–7, oversize-linje, lock-guard
  på alle beskyttede kommandoer, og auto-lock som låser seg selv etter angitt
  timeout.
- **Separate lagre bekreftet.** Sletting av konsoll-slot 0 (som låser enheten)
  påvirker ikke det separate CTAP2-credential-lageret; SSH-innlogging fungerer
  fortsatt.

Testartefakter og skript ligger i `/tmp/fjaeger-ssh-test/`:
`fido2_client_test.py` (python3-fido2) og `console_regression.py` (42 sjekker).
Donglen ble etterlatt **låst**, slot 0 provisionert, timeout 0, med åtte
CTAP2-credentials og test-PIN `12345`. Testnøkler i
`/tmp/fjaeger-ssh-test/id_ecdsa_sk_{working,2..8}`.

## Rask OpenSSH-regresjonstest

Finn riktig HID-enhet; ikke anta at den alltid er `/dev/hidraw2`. Lås deretter
opp via CDC-konsollen:

```text
UNLOCK 12345
STATUS
```

Opprett en ny testnøkkel:

```bash
ssh-keygen -t ecdsa-sk \
  -O device=/dev/hidraw2 \
  -f /tmp/fjaeger_test_key \
  -N '' \
  -C fjaeger-test
```

Signer en fil:

```bash
ssh-keygen -Y sign \
  -f /tmp/fjaeger_test_key \
  -n fjaeger-test \
  /tmp/message.txt
```

Lag en `allowed_signers`-fil med public key på denne formen:

```text
fjaeger-test sk-ecdsa-sha2-nistp256@openssh.com AAAA...
```

Verifiser:

```bash
ssh-keygen -Y verify \
  -f /tmp/allowed_signers \
  -I fjaeger-test \
  -n fjaeger-test \
  -s /tmp/message.txt.sig \
  < /tmp/message.txt
```

Kjør deretter `LOCK` og kontroller at en ny signering mislykkes. OpenSSH viser
foreløpig en generell feil som `invalid format`; viktigste sikkerhetsegenskap er
at ingen signatur returneres.

## Vedvarende kryptert MSC-disk (implementert 2026-09-26)

MSC-disken ble gjort til en **12 MiB vedvarende flash-partisjon** og frikoblet
fra keyslots.

- **Partisjon:** `0x10100000`–`0x10D00000` (12 MiB), som offset `0x00100000`
  fra XIP. Firmware (~128 KB) ligger før dette; PIN/slots/CTAP2/disknøkkel
  ligger i de siste 8 KiB. Ingen overlapp.
- **Filsystem:** FAT16, 512-byte-sektorer, 1 sektor/cluster. Metadata (boot,
  begge FAT-er, rotkatalog) initialiseres én gang ved første oppstart;
  dataregionen skrives lazy. Erstatter den gamle 8 KiB RAM-disken.
- **Kryptering:** AES-128-XTS, dedikert permanent disknøkkel lagret i lageret,
  sektor-LBA som tweak. Disken er **uavhengig av keyslots** — `KEY SELECT`,
  `KEY PROVISION` og `KEY ERASE` påvirker ikke diskdata.
- **Deferred write-behind:** USB MSC-callbacker køer sektor-skriver i en
  pending-kø; selve flash-erase/program skjer i `fj_msc_task()` (main-loop),
  aldri inne i en USB-transaksjon. Data flusher ved `LOCK`/unmount
  (`fj_msc_set_ready(false)`) og kontinuerlig i main-loop.
- **Integritet:** en vedvarende CRC-32-tabell (én per 4 KiB-blokk, lagret i
  klartekst i de siste 4 blokkene av partisjonen) verifiseres ved mount.
  Korrupsjon fra strømbrudd eller tukling oppdages, og disken re-initialiseres
  i stedet for å serve korrupte data.
- **Uavhengig disk-lås:** `UNLOCK <pin>` låser bare opp **enheten** (nøkler);
  den krypterte disken er et separat steg via `DISK UNLOCK`/`DISK LOCK`/
  `DISK STATUS`. `LOCK` og auto-relåsing lukker også disken; `DISK UNLOCK`
  krever at enheten er ulåst. Når disken er låst er den utilgjengelig
  (NOT_READY).

Fysisk verifisert:
- Disken mountes som ~12 MiB vfat-volum når ulåst.
- Filer skrevet og lest tilbake korrekt (1 MiB-binærfil + tekstfil).
- **Data overlever watchdog-`RESET` og kaldstart**, over flere skrive/reboot-
  sykluser (deferred write + CRC-tabell oppdateres og verifiseres korrekt).
- Slottbytte (slot 0 → 1) endrer **ikke** diskdata — disknøkkel er uavhengig.
- **Uavhengig tilstand:** `UNLOCK` gir `state: unlocked` mens `disk: locked`
  (disken ikke mountet); `DISK UNLOCK` mountet den som eget steg; `DISK LOCK`
  unmountet disken mens enheten forble ulåst; `LOCK` lukket både enhet og disk;
  `DISK UNLOCK` med enheten låst ga `ERR device locked`.
- **Integritetsdeteksjon:** ved å erase boot-blokken (0xFF) uten å oppdatere
  CRC-tabellen, oppdaget enheten korrupsjonen og re-initialiserte filsystemet
  (eksisterende filer borte) — korrupte data serveres ikke.
- Under feilsøking ble en adresse-bug rettet: `DISK_FLASH_START` må være en
  XIP-offset, ikke absolutt adresse (feil ga hard fault på `0x20100000`).
- En CRC-tabell-bug ble rettet: magic/header kolliderte med `CRC[0]` og ga
  falsk mismatch ved mount (data "forsvant" ved reboot). Fikset ved å reservere
  en header-offset (`CRC_HEADER_SIZE`) som ikke overlapper CRC-ene.

Kjent avveining: hver skriveoperasjon til en ny flash-blokk krever flash-erase
av en 4 KiB-blokk, så store filer skrives tregt og sliter på flash. Filsystemet
er FAT16 (maks ~2 GB med passende cluster), men partisjonen er 12 MiB. Det er
ingen wear-leveling; de mest skrevne sektorene (FAT, rotkatalog) slites fortere.

## Dette bør testes videre

Prioritert liste for neste utviklingsøkt (punkter som nå er fullført og
verifisert er fjernet — se «Fysisk verifisert 2026-09-26» over):

1. **Flere FIDO-klienter / OS.** Prøv nettleser/WebAuthn og gjerne både Linux og
   Windows/macOS. Test også flere tilkoblede FIDO-enheter samtidig.
2. **Avbrudd og feiltrafikk.** Test CTAPHID CANCEL, kanal-lock, fragmenterte og
   maksimalt store meldinger, feil sekvensnummer og USB-frakobling midt i svar.
3. **Langtidstest.** Kjør mange signeringer, lås/ulås-sykluser og auto-lock mens
   HID og MSC brukes samtidig. Se etter USB-reset, heap-/stackproblemer og
   flashslitasje.
4. **MSC-dataintegritet.** Skriv og les filer over mange lock/unlock-sykluser,
   auto-lock under I/O og bytte av aktiv slot. Disken er nå en vedvarende
   flash-partisjon (12 MiB) med dedikert disknøkkel; verifiser at innhold aldri
   lekker klartekst mens den er låst, og at data overlever reboot.
5. **LED-regresjon.** Bekreft visuelt rød/grønn/gul og at blå aktivitetspuls ikke
   skjuler låsestatus for lenge, særlig under kontinuerlig disk- eller HID-I/O.
6. **Reell innlogging på ekstern vert.** Denne økten brukte en lokal `sshd`;
   verifiser også mot en fjerntliggende/tjenestevert.

## Kjente begrensninger og sikkerhetsarbeid

- PIN og PUK sendes som kommandotekst over CDC. Fastvaren ekkoer ikke input og
  nullstiller kommandobufferen etter bruk, men brukeren må slå av lokal echo og
  eventuell logging i terminalprogrammet.
- PIN lagres som usaltet SHA-256. Det må erstattes med saltet, treg
  nøkkelavledning. Enhets-PIN og disk-PIN sperres nå etter fem feil, og fem
  feil PUK-forsøk sletter flashlageret, men det mangler fortsatt tidsforsinkelse.
- Det finnes ingen egen fysisk touch-knapp. CTAP `up` representerer i praksis at
  enheten allerede er låst opp via PIN, ikke en ny fysisk bekreftelse per bruk.
- Full U2F/CTAP1 er ikke implementert. Bare kompatibilitetsproben som OpenSSH/
  libfido2 trenger for tokenvalg finnes.
- Bare ES256 / P-256 støttes. `ed25519-sk` støttes ikke.
- CTAP2-implementasjonen er et nødvendig delsett, ikke en sertifisert komplett
  FIDO2-autentikator. Blant annet mangler credential management og CTAP reset.
- Signaturtelleren er null fordi en flyktig teller ville gått bakover etter
  reboot. Persistent monotonteller er ikke implementert.
- MSC er nå en **12 MiB vedvarende FAT16-partisjon** i on-board-flash, AES-XTS-
  kryptert i farten med en **dedikert disknøkkel** (uavhengig av keyslots).
  Filsystemets metadata initialiseres én gang; dataregionen skrives lazy.
  Skriving av store filer er treg og sliter på flash (hver sektoroppdatering
  krever flash-erase av en 4 KiB-blokk). Flash-layout: firmware ~128 KB fra
  `0x10000000`, disk-partisjon 12 MiB fra `0x10100000` (offset `0x00100000`),
  lager i de siste 8 KiB.
- AES-XTS gir konfidensialitet, men ikke autentisering eller integritetsvern.
- Nøkler ligger i vanlig ekstern flash; secure boot, signert firmware,
  flashbeskyttelse og motstand mot fysisk uttrekk er ikke ferdigstilt.
- Flashlageret bruker A/B og CRC, men trenger egne tester for strømbrudd akkurat
  under erase/program og for generasjonsteller-wrap.

## Anbefalt videre rekkefølge

1. Testpunktene 1–4 over er kjørt og resultatene dokumentert i «Fysisk
   verifisert 2026-09-26». Fortsett med de gjenværende punktene i «Dette bør
   testes videre».
2. Legg til automatiserte parser- og transporttester for CTAPHID/CBOR.
3. Erstatt raske PIN-/PUK-hasher med en saltet, treg KDF og legg til
   tidsforsinkelse i tillegg til de vedvarende forsøkstellerne.
4. Bestem om prosjektet skal ha fysisk bekreftelsesknapp for korrekt FIDO
   user-presence-semantikk.
5. **Vedvarende MSC-partisjon er implementert** (12 MiB, dedikert disknøkkel,
   XTS). Gjenværende: optimaliser skriveytelse/slitasje (f.eks. skriv-innsamling
   og lavere erase-frekvens), vurder FAT32 om kapasiteten økes, og vurder
   integritetsbeskyttelse per sektor.
6. Planlegg secure boot, signerte oppdateringer og nøkkelbeskyttelse før bruk med
   reelle hemmeligheter.

## Relevante commits

```text
3c2ad51  Lokal baseline
70f0fef  Document physical console and persistence tests
5f1ac23  Fix CTAP2 OpenSSH enrollment and signing
```
