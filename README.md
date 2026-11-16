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

## Protocol, in short

```
frame = seqId (uint16 LE) + opcode (uint8) + payload
```

| | UUID | role |
|---|---|---|
| command | `60133d5c-…` | write without response |
| reply | `8dc5ec05-…` | notify (command replies) |
| event | `43312cd1-…` | notify (async events) |

Opcodes: `0x00` getAccessSeed, `0x01` unlock, `0x02` getLimits, `0x10`
readShort, `0x11` writeShort, `0x22` write, `0x03` ack/flow. A `readShort` reply
is `seqId(2) + status(1, 0x00=OK) + value`. Device state is addressed as little
filesystem-like paths (`/p/bat/soc`, `/p/app/htr/temp`, …); the type registry in
the script maps the ones I've identified.

## Credit

The protocol was confirmed against my own captures plus the prior work in
[austenstone/puffco-mcp](https://github.com/austenstone/puffco-mcp) and
Fr0st3h's write-up. The GATT UUIDs and the auth scheme line up with those.

## Use it on your own device

This is for understanding and interoperating with a Puffco you own. Don't use it
against devices that aren't yours.

## License

GPL-3.0. See [LICENSE](LICENSE).
