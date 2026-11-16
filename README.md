<p align="center">
  <img src="assets/logo.png" width="320"
       alt="Badge: a weathered metal medallion reading PUFFCO LORAX over
            DECODE TOOL, with a glowing Bluetooth padlock, a Puffco device,
            and a laptop receiving a stream of bits, on a circuit-board field.">
</p>

# puffco-lorax-decode

A small Python decoder for Puffco **LORAX** BLE traffic. Feed it an Android
`btsnoop_hci.log` and it prints the auth handshake, every device path the app
read with its value decoded by type, and every control command it wrote.

LORAX is the path-based command channel the newer Puffco firmware (New Proxy /
Peak Pro) uses instead of the old one-characteristic-per-field GATT. This is the
decoder from my write-up on reverse-engineering it:
**[Reverse-Engineering a Bluetooth LE Protocol from Android](https://magikh0e.pl/pubHardwareHacking/reversing-bluetooth-le-android.html)**,
where the whole method (capture, decode, read the app for the auth secret) is
walked through end to end.

## Usage

```bash
python3 puffco_lorax_decode.py btsnoop_hci.log [--json out.json] [--csv out.csv]
```

No dependencies beyond the Python 3 standard library.

Grab the capture from an Android phone with Developer Options → **Enable
Bluetooth HCI snoop log**, pair and use the real app, then pull
`btsnoop_hci.log` off the device. Start the log *before* the app connects if you
want the auth handshake in it.

## What it prints

- **Auth** — the `getAccessSeed` → `unlock` pair, and whether the computed
  token matches the one the app actually sent (a known-answer check that your
  handshake code is right).
- **Device path map** — every `readShort` path the app pulled, with the value
  decoded as float32 / u32 / string / rgb / mac / bytes, plus a short
  description. `--json` / `--csv` write the same table to a file.

## Live client: `puffco_client.py`

The decoder works offline, from a capture. The companion client goes the other
way round: it connects to a Puffco over BLE, runs the LORAX auth handshake, and
reads live device state (battery, heater temp, serial, profiles, and so on) using
the same seqId transaction model. Cross-platform via
[`bleak`](https://github.com/hbldh/bleak).

```bash
pip install bleak
python3 puffco_client.py                      # auto-scan for a Puffco
python3 puffco_client.py --name "PEAK PRO"
python3 puffco_client.py --address AA:BB:CC:DD:EE:FF
```

It reads today; *writing* (set temp, start a cycle) is the next step — see the
roadmap below.

## Protocol, in short

```
frame = seqId (uint16 LE) + opcode (uint8) + payload
```

| | UUID | role |
|---|---|---|
| command | `60133d5c-…` | write without response |
| reply | `8dc5ec05-…` | notify (command replies) |
| event | `43312cd1-…` | notify (async events) |

LORAX is a small **file-access protocol** — the paths are files, and
`readShort` / `writeShort` are shorthand for open+read / open+write+close. The
full opcode set:

| group | opcodes |
|---|---|
| auth / session | `0x00` getAccessSeed · `0x01` unlockAccess · `0x02` getLimits · `0x03` ackEvents |
| shorthand | `0x10` readShort · `0x11` writeShort · `0x12` statShort · `0x13` unlink |
| file handles | `0x20` fileOpen · `0x21` fileRead · `0x22` fileWrite · `0x23` fileWatch · `0x24` fileUnwatch · `0x25` fileStat · `0x26` fileClose · `0x27` pruneFileHandles |

A reply is `seqId(2) + status(1, 0x00=OK) + data`. Payloads:
`readShort = offset(u16) maxLen(u16) path`;
`writeShort = offset(u16) flags(u8) path 0x00 data` (flags: truncate = `0x04`).
Device state is addressed as filesystem-like paths (`/p/bat/soc`,
`/p/app/htr/temp`, …); the type registry in the script maps the ones I've
identified.

## Credit

The protocol was confirmed against my own captures plus prior work. The LORAX
UUIDs and the path model match
[austenstone/puffco-mcp](https://github.com/austenstone/puffco-mcp).
[Fr0st3h's write-up](https://github.com/Fr0st3h/Puffco-Reverse-Engineering-Writeup)
documents the *older* one-characteristic-per-field firmware — a different GATT
layout and a different handshake constant — but the same
`SHA-256(secret ++ seed)[:16]` auth scheme carried over to LORAX.

The full opcode set (LORAX is a file-access protocol) and the
`readShort`/`writeShort` payload layouts were recovered from Puffco Connect
3.13.47 while building my own Puffco Pro control webapp, and folded back in here.

## Status / work in progress

This decoder is step one of a bigger itch: there's no official public API for
these devices, so the only way to talk to a Puffco you own on your own terms is
to work out the protocol from the wire. Right now this repo *reads* — it turns a
capture into a documented path map. The direction I'm poking at is turning that
understanding into something you can actually *drive* a device with: a small,
dependency-light integration or app that isn't the official one. I did the same
reverse-engineering route for Storz & Bickel (see
[volcano-hybrid-control](https://github.com/magikh0e/volcano-hybrid-control) and
[home-assistant-volcano-hybrid](https://github.com/magikh0e/home-assistant-volcano-hybrid));
this is the early, exploratory version of that for LORAX.

What's mapped so far:

- The frame format, the command/reply/event channels, and the **full opcode set**
  — LORAX is a file-access protocol (open/read/write/watch/stat/close), with
  `readShort`/`writeShort` as the shorthand ops.
- The New Proxy auth handshake, confirmed against a real capture.
- A chunk of the `/p` and `/u` path tree with types (battery, heater, odometer,
  profiles, lantern, LEDs, device info).

Still open, and where help is useful:

- More of the path tree, and which paths are writable vs read-only.
- Which **writeShort** paths and values actually drive the device (set temp,
  start / abort a heat cycle) — the opcode and framing are known; the control
  *paths* are the remaining piece.
- The event channel (`43312cd1-…`): what the device pushes unprompted.
- Whether paths/opcodes drift across firmware versions.
- Nailing down the control surface enough to safely *write* (set temp, trigger a
  cycle) rather than only read.

A useful lead for those write opcodes:
[Fr0st3h's write-up](https://github.com/Fr0st3h/Puffco-Reverse-Engineering-Writeup)
lists the older firmware's command set (heatCycleStart, heatCycleAbort, bonding,
lighting modes). It's a different generation and a different wire format, but the
device *behaviours* are the same — so it's a decent map of **which commands exist**
to match against the LORAX writes when decoding them.

If you've captured something new, or decoded a path the registry doesn't know,
**[Discussions](https://github.com/magikh0e/puffco-lorax-decode/discussions)** is
the place — there's a form for findings. This is exploratory and done on my own
devices; nothing here is affiliated with or endorsed by Puffco.

## Use it on your own device

This is for understanding and interoperating with a Puffco you own. Don't use it
against devices that aren't yours.

## License

GPL-3.0. See [LICENSE](LICENSE).
