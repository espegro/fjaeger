# TODO: profiler for SSH/FIDO-credentials

## Mål

Gjør dagens konsoll-slots om til navngitte profiler, for eksempel «Privat»,
«Jobb» og «Administrasjon». Hver profil skal ha flere selvstendige
SSH/FIDO-credentials. Bare credentials i valgt profil skal kunne brukes eller
oppdages. Enrollment skal automatisk knytte nye credentials til valgt profil.

Dette dokumentet er implementeringsgrunnlag for OpenCode. Profilfunksjonen er
ikke implementert ennå.

## Dagens situasjon

- `KEY PROVISION`, `KEY SELECT`, `KEY LIST` og `KEY ERASE` håndterer åtte
  konsoll-slots med egne ECDSA-/AES-nøkler i `src/core/keys.c`.
- CTAP2 har et separat lager med åtte credentials. Hvert credential har sin
  egen private P-256-nøkkel og credential-ID.
- CTAP2 bruker ikke valgt konsoll-slot. Alle credentials kan brukes når
  enheten er ulåst, uansett `KEY SELECT`.
- Den krypterte MSC-disken har en separat disknøkkel og disk-PIN.
- Aktiv slot er foreløpig bare en RAM-verdi og starter på slot 0 ved boot.
- Auto-lock er 900 sekunder som standard. `TIMEOUT` lagres permanent;
  `TIMEOUT 0` deaktiverer auto-lock. Enhetslås lukker også disken.

Relevante filer: `src/core/keys.h/.c`, `src/core/state.h/.c`,
`src/fido/ctap2.h/.c` og `src/usb/cdc_console.c`.

## Foreslått modell

1. Behold opptil åtte profiler, identifisert med ID 0–7 og et navn.
2. En profil er metadata og et tilgangsfilter. Den skal ikke generere en felles
   privatnøkkel for alle sine credentials.
3. Hvert CTAP2-credential får en `profile_id`, men beholder sin egen tilfeldig
   genererte private nøkkel, credential-ID og RP-binding.
4. Behold foreløpig åtte credentials totalt, fordelt fritt mellom profilene.
   Åtte profiler betyr ikke åtte credentials per profil. En større kapasitet
   kan vurderes separat; A/B-recorden må fortsatt passe i én 4 KiB-sektor.
5. På et tomt lager opprettes profil 0 med navnet «Default», og denne velges.
6. Lagre valgt profil permanent. Ved boot skal den valgte profilen finnes;
   ellers velges en gyldig profil med en tydelig definert fallback.
7. Enhets-PIN og recovery-PUK er fortsatt felles for hele donglen.
8. MSC-disken er fortsatt felles og uavhengig av profilvalg. Profilbytte eller
   profilsletting skal ikke endre disk-PIN, disknøkkel eller diskdata.

Eksempel:

| Profil | Credentials |
|---|---|
| 0: Privat | Privat server, GitHub |
| 1: Jobb | Jobbserver, GitLab |
| 2: Administrasjon | Driftsserver |

Når profil 1 er valgt, skal en signeringsforespørsel med credential-ID fra
profil 0 avvises. SSH-filen på PC-en peker fortsatt på samme credential-ID;
brukeren må velge riktig profil før den kan brukes.

Profilene gir organisering og tilgangsstyring i fastvaren. Med felles PIN og
fri profilvelging er de ikke separate sikkerhetsdomener med egne brukere.

## Konsollkommandoer

Bruk tydelige `PROFILE`-kommandoer som hovedgrensesnitt:

| Kommando | Foreslått oppførsel |
|---|---|
| `PROFILE LIST` | Vis ID, navn, aktiv markering og antall credentials |
| `PROFILE CREATE <id> <name>` | Opprett en tom profil; avvis eksisterende ID |
| `PROFILE SELECT <id>` | Velg og lagre aktiv profil; avvis ukjent ID |
| `PROFILE RENAME <id> <name>` | Endre navn uten å endre credentials |
| `PROFILE ERASE <id>` | Slett profilen og alle dens credentials |

- Muterende kommandoer krever ulåst enhet, som dagens `KEY`-kommandoer.
- `STATUS` skal vise aktiv profil og relevant credential-antall.
- Avvis sletting av aktiv profil; brukeren må velge en annen først. Dermed
  finnes alltid minst én profil og aktiv profil forblir gyldig.
- Ikke la `CREATE` eller `RENAME` overskrive en profil eller dens credentials.
- Definer og dokumenter grenser for navn og ID. Enkle navn uten mellomrom er
  tilstrekkelig i første versjon.
- Fjern eller avvikle de gamle `KEY`-kommandoene tydelig. Ikke behold en
  misvisende `KEY PROVISION` som genererer nøkler CTAP2 aldri bruker.

## CTAP2-endringer

- [ ] `makeCredential` knytter credentialet til aktiv profil.
- [ ] `getAssertion` med `allowList` godtar bare credentials i aktiv profil.
- [ ] Credential-ID og RP-hash skal begge valideres før signering.
- [ ] Søk uten `allowList` skal også filtrere på aktiv profil.
- [ ] `excludeList` må håndteres korrekt. Kontroller eksisterende ID/RP-binding
      på tvers av profiler og avvis dublettregistrering uten å røpe profilnavn.
- [ ] Profilbytte/sletting ugyldiggjør eventuell pågående assertion-enumerering
      og annen bufret credential-seleksjon.
- [ ] Låst enhet avviser fortsatt enrollment og signering.

I første versjon beholdes ECDSA P-256/ES256. Ed25519 er ikke en del av denne
oppgaven.

## Lagring og sletting

- [ ] Erstatt de gamle slot-nøklene med profilmetadata; ikke behold ubrukt
      privat-/AES-nøkkelmateriale.
- [ ] Utvid credentialformatet med profil-ID og lagre aktiv profil.
- [ ] Bump flashformatversjonen. Utviklingsdata kan tapes; migrering er ikke
      nødvendig. Dokumenter at eksisterende credentials må enrolles på nytt.
- [ ] Behold A/B-format, generasjonsteller, CRC og størrelsessjekk for 4 KiB.
- [ ] Profilsletting oppdaterer både persistent lager og CTAP2-cachen med én
      konsistent operasjon. En gammel cache må ikke kunne skrive slettede
      credentials tilbake til flash via en utsatt flush.
- [ ] Dokumenter at vanlig A/B-sletting kan etterlate nøkkelmateriale i den
      eldre flashkopien frem til den overskrives. Ikke påstå fysisk sikker
      sletting av enkeltprofiler uten å implementere og teste dette.
- [ ] Factory-wipe sletter fortsatt begge flashkopier og alt live
      nøkkelmateriale, inkludert profil- og credential-tilstand.

## Resident credentials: egen oppfølgingsoppgave

Profiler skal utformes slik at resident/discoverable credentials senere kan
brukes innenfor aktiv profil. Dette krever mer enn å annonsere `rk: true`:

- Lagre resident-markering, RP-informasjon og user-ID/metadata korrekt.
- Implementere korrekt user-entity i assertion-responsen.
- Håndtere flere treff med `numberOfCredentials` og `getNextAssertion`.
- Implementere nødvendige credential-management- og autentiseringsfunksjoner
  for at OpenSSH/libfido2 faktisk kan hente nøkler med `ssh-keygen -K`.
- Oppdagelse og eksport av credential-håndtak skal bare vise aktiv profil.
- Teste `ssh-keygen -t ecdsa-sk -O resident` og `ssh-keygen -K` ende til ende.

Dagens søk etter RP-hash alene er ikke full resident-støtte. Privatnøkler skal
aldri eksporteres; det som kan hentes til PC-en er credential-håndtak og public
key. Resident-støtte kan implementeres etter at profilisolasjonen fungerer.

## Akseptansetester

- [ ] Tom enhet starter låst med profil 0 «Default» og timeout 900 sekunder.
- [ ] Opprett profil A og B, enroll minst to credentials i A og ett i B.
- [ ] Alle A-credentials signerer når A er valgt; B-credentialet avvises.
- [ ] Etter bytte til B er resultatet motsatt.
- [ ] Feil profil, feil RP og ukjent credential-ID returnerer ingen signatur.
- [ ] Profilvalg, navn og credential-binding overlever reset og kaldstart.
- [ ] Sletting av en inaktiv profil gjør dens credentials ubrukelige
      umiddelbart og etter omstart. Andre profiler fungerer fortsatt.
- [ ] Sletting av aktiv profil og overskriving via `CREATE` avvises.
- [ ] Fullt credentiallager avvises uten å endre eksisterende credentials.
- [ ] Lås/auto-lock avviser signering og lukker MSC uansett valgt profil.
- [ ] Profilbytte og profilsletting påvirker ikke diskdata.
- [ ] Factory-wipe etter fem feil PUK-forsøk tømmer alle profiler og
      credentials; ved neste oppstart opprettes tom «Default»-profil.
- [ ] Eksisterende hosttester og firmwarebygg består. Legg til hosttester som
      spesielt dekker profilfilter og cache-/persistenssamspill.
- [ ] Fysisk OpenSSH-regresjon: enroll, sign, verify og reell SSH-innlogging
      med credentials fra minst to profiler.

## Foreslått implementeringsrekkefølge

1. Modell og persistent profilmetadata, inkludert tom Default-profil.
2. Profilkommandoer og validering i konsollen.
3. Profilbinding ved enrollment og filtrering av alle credential-oppslag.
4. Konsistent profilsletting og håndtering av live CTAP2-cache.
5. Hosttester, firmwarebygg og fysisk OpenSSH-regresjon.
6. Oppdater README.md og STATUS.md med faktisk testet oppførsel.
7. Resident credentials som separat utvidelse.
