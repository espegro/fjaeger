# Monocypher vendoring record

- Upstream: https://github.com/LoupVaillant/Monocypher
- Version: 4.0.3
- Source archive: `4.0.3.tar.gz`
- Archive SHA-256: `a7cbae546fbdc489bca632c3747e1ceb8ca3d4bd39e2706a0916f28ccd280e50`
- Imported files: `src/monocypher.{c,h}` and
  `src/optional/monocypher-ed25519.{c,h}`
- License: BSD-2-Clause OR CC0-1.0, reproduced in each upstream source file.

Only the Ed25519/SHA-512 compatibility implementation is used by Fjaeger. The
core file is also compiled because the optional implementation shares
Monocypher's constant-time curve arithmetic and wipe primitives.
