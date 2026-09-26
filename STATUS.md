# Fjaeger — status og overlevering

Oppdatert: 2026-09-26

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

## Dette bør testes videre

Prioritert liste for neste utviklingsøkt:

1. **Reell SSH-innlogging.** `ssh-keygen` enroll/sign/verify virker, men faktisk
   innlogging mot en `sshd` med nøkkelen i `authorized_keys` er ikke prøvd.
2. **Kaldstart og utholdenhet.** Koble strømmen helt fra, start igjen, lås opp og
   signer med eksisterende credential. Gjenta etter flere firmwareflasher.
3. **Flere credentials.** Opprett, bruk og gjenfinn alle åtte CTAP2-plassene;
   test fullt lager, duplikater og credentials for flere RP-ID-er.
4. **Flere FIDO-klienter.** Prøv `fido2-token`, nettleser/WebAuthn og gjerne
   både Linux og Windows/macOS. Test også flere tilkoblede FIDO-enheter.
5. **Avbrudd og feiltrafikk.** Test CTAPHID CANCEL, kanal-lock, fragmenterte og
   maksimalt store meldinger, feil sekvensnummer og USB-frakobling midt i svar.
6. **Langtidstest.** Kjør mange signeringer, lås/ulås-sykluser og auto-lock mens
   HID og MSC brukes samtidig. Se etter USB-reset, heap-/stackproblemer og
   flashslitasje.
7. **MSC-dataintegritet.** Skriv og les filer over mange lock/unlock-sykluser,
   auto-lock under I/O og bytte av aktiv slot. RAM-disken skal miste innhold ved
   reboot, men må aldri lekke klartekst mens den er låst.
8. **LED-regresjon.** Bekreft visuelt rød/grønn/gul og at blå aktivitetspuls ikke
   skjuler låsestatus for lenge, særlig under kontinuerlig disk- eller HID-I/O.
9. **Konsollregresjon etter siste FIDO-endringer.** Kjør hele kommandolisten én
   gang til og verifiser feiltilfeller, grenselengder og slot 0–7.

## Kjente begrensninger og sikkerhetsarbeid

- PIN sendes og vises i klartekst på CDC-konsollen.
- PIN lagres som usaltet SHA-256. Det må erstattes med saltet, treg
  nøkkelavledning, og feilforsøk trenger ratebegrensning/forsinkelse.
- Det finnes ingen egen fysisk touch-knapp. CTAP `up` representerer i praksis at
  enheten allerede er låst opp via PIN, ikke en ny fysisk bekreftelse per bruk.
- Full U2F/CTAP1 er ikke implementert. Bare kompatibilitetsproben som OpenSSH/
  libfido2 trenger for tokenvalg finnes.
- Bare ES256 / P-256 støttes. `ed25519-sk` støttes ikke.
- CTAP2-implementasjonen er et nødvendig delsett, ikke en sertifisert komplett
  FIDO2-autentikator. Blant annet mangler credential management og CTAP reset.
- Signaturtelleren er null fordi en flyktig teller ville gått bakover etter
  reboot. Persistent monotonteller er ikke implementert.
- MSC er en **8 KiB RAM-disk**, ikke persistent lagring i flash.
- AES-XTS gir konfidensialitet, men ikke autentisering eller integritetsvern.
- Nøkler ligger i vanlig ekstern flash; secure boot, signert firmware,
  flashbeskyttelse og motstand mot fysisk uttrekk er ikke ferdigstilt.
- Flashlageret bruker A/B og CRC, men trenger egne tester for strømbrudd akkurat
  under erase/program og for generasjonsteller-wrap.

## Anbefalt videre rekkefølge

1. Kjør testpunktene 1–4 over og noter eksakte klient-/OS-resultater her.
2. Legg til automatiserte parser- og transporttester for CTAPHID/CBOR.
3. Herd PIN-håndtering og legg til forsøksteller/ratebegrensning.
4. Bestem om prosjektet skal ha fysisk bekreftelsesknapp for korrekt FIDO
   user-presence-semantikk.
5. Design en eksplisitt, persistent og integritetsbeskyttet flashpartisjon for
   diskdata dersom MSC skal være mer enn en prototype.
6. Planlegg secure boot, signerte oppdateringer og nøkkelbeskyttelse før bruk med
   reelle hemmeligheter.

## Relevante commits

```text
3c2ad51  Lokal baseline
70f0fef  Document physical console and persistence tests
5f1ac23  Fix CTAP2 OpenSSH enrollment and signing
```
