# Fuzzing (FJ-N009)

Coverage-guidance fuzz targets for the parsers, buildable either with
libFuzzer (clang) or a plain gcc + ASAN driver (CI).

Targets:

- `fz_cbor` — deep-walks `fj_cbor_next`/`fj_cbor_read_bytes`/… over `cbor.c`.
- `fz_ctap2` — feeds every CTAP2 command (makeCredential, getAssertion,
  clientPin, credentialManagement, getNextAssertion, getInfo) with the same
  input against a store that already holds a resident credential, so the
  sign/enumeration paths run deep.

Properties asserted: no OOB reads/writes, no integer-overflow bounds bypass,
no hangs; malformed CBOR is rejected.

## libFuzzer (clang)

```
clang -std=c11 -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined \
      -Isrc/core -Isrc/fido fuzz/fz_cbor.c src/fido/cbor.c -o /tmp/fz_cbor
clang -std=c11 -Wall -Wextra -Werror -fsanitize=fuzzer,address,undefined \
      -Isrc/core -Isrc/fido fuzz/fz_ctap2.c src/fido/ctap2.c src/fido/cbor.c \
      src/fido/pin.c fuzz/stubs.c -o /tmp/fz_ctap2

/tmp/fz_cbor   -max_len=2048 -runs=30000 fuzz/corpus
/tmp/fz_ctap2  -max_len=2048 -runs=30000 fuzz/corpus
```

## gcc + ASAN driver (no clang)

```
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
   -Isrc/core -Isrc/fido -Isrc/led fuzz/driver.c fuzz/fz_cbor.c src/fido/cbor.c \
   -o /tmp/drv_cbor
cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined \
   -Isrc/core -Isrc/fido -Isrc/led -DFZ_CTAP2 fuzz/driver.c fuzz/fz_ctap2.c \
   src/fido/ctap2.c src/fido/cbor.c src/fido/pin.c fuzz/stubs.c -o /tmp/drv_ctap2

/tmp/drv_cbor  fuzz/corpus/*
/tmp/drv_ctap2 fuzz/corpus/*
```
