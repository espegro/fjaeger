# Fjaeger TUI

A self-contained terminal controller for the Fjaeger security key over its USB
serial (CDC) console. Pure Go + [bubbletea](https://github.com/charmbracelet/bubbletea);
it builds with a plain `go build` on any Linux — no X11/Wayland dev headers, no
GUI libraries, no sudo. It also works over SSH/tmux and in a framebuffer.

## Build

```bash
cd tui
go build -o fjaeger-tui .     # or: make
./fjaeger-tui                 # interactive TUI
```

Note: `go.bug.st/serial` is pure Go, so the binary is a single file with
no runtime dependencies beyond glibc.

## Usage

- **Interactive:** `./fjaeger-tui`. Pick a serial port (`↑/↓`, `Enter`), then
  navigate the menu. Secrets (passphrase, PIN, PUK, disk PIN) are entered in
  masked fields. Destructive actions ask for confirmation (`y/N`).
- **Script / single command:** `./fjaeger-tui /dev/ttyACM0 PROFILE LIST`
  prints the raw reply. Useful for automation and quick checks.

Menu covers: status (live), lock/unlock (pass and PUK), set passphrase / CTAP2 PIN /
PUK, auto-lock timeout, backup/restore, reboot / reboot-to-bootsel, and a raw
console.

Profiles, Credentials and Disk each open a single, dedicated screen (arrow
up/down navigation where a list is shown):

- **Profiles** — table of profiles with the active one marked. Keys: `s` set
  active, `e` rename, `n` create, `x` erase, `g` refresh.
- **Credentials** — table of credentials in the active profile. Keys: `d`
  delete, `g` refresh.
- **Disk** — live `DISK STATUS`, plus operations. Keys: `g` refresh,
  `u` unlock, `l` lock, `f` force lock, `p` set disk PIN, `b` unblock (PUK),
  `x` format.

Destructive actions ask for confirmation (`y/N`); rename/create and the disk
PIN/PUK/UNLOCK prompts use an inline input field.

## Device access

The dial-out user needs `dialout` group access:
`sudo usermod -aG dialout $USER`, then log out/in.

## How it talks to the device

Line protocol: send `COMMAND arg\r\n`, the device replies and ends with the
`fjaeger> ` prompt. Commands carry their arguments inline (e.g. `UNLOCK <pass>`),
so the device never enters its interactive secret-entry mode. The echoed copy
of an inline secret is stripped from replies so nothing is shown on screen.
