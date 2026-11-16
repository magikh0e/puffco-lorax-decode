#!/usr/bin/env python3
"""
puffco_client.py — minimal Puffco New Proxy / Peak Pro (LORAX) BLE client.

Connects, runs the LORAX auth handshake, and reads live device state using the
seqId transaction model. Pure-Python, cross-platform via `bleak`.

    pip install bleak
    python3 puffco_client.py                 # auto-scan for a Puffco
    python3 puffco_client.py --name "PEAK PRO"
    python3 puffco_client.py --address AA:BB:CC:DD:EE:FF

REQUIRED: the BLE link must be PAIRED and ENCRYPTED first, or the Peak Pro
silently ignores every LORAX frame and this client just hangs on timeouts (no
replies at all). Put the Peak in pairing mode (hold the button until the logo
glows blue), then pair it with your OS:
  * Linux / macOS: the OS Bluetooth settings, or bluetoothctl.
  * Windows: Settings / Chrome often will NOT pair it -- use a ConfirmOnly
    custom pairing (DeviceInformationCustomPairing, auto-accept). If pairing
    sticks on OPERATION_ALREADY_IN_PROGRESS, a reboot clears it.

Protocol (live-verified on a Peak Pro, fw gith 5652c02, bleak 3.1):
  frame  = seqId(u16 LE) + opcode(u8) + payload
  reply  = seqId(u16 LE) + errByte(u8) + data      (on the REPLY notify char)
  auth   = getAccessSeed -> token = SHA256(HANDSHAKE2 ++ seed)[:16] -> unlock
Values on this firmware are float32 LE / ASCII / packed RGB bytes.
"""
import argparse, asyncio, base64, hashlib, struct
from bleak import BleakClient, BleakScanner

# --- Confirmed GATT UUIDs ------------------------------------------------
SERVICE = "e276967f-ea8a-478a-a92e-d78f5dd15dd5"
COMMAND = "60133d5c-5727-4f2c-9697-d842c5292a3c"  # write w/o response
REPLY   = "8dc5ec05-8f7d-45ad-99db-3fbde65dbd9c"  # notify: command replies
EVENT   = "43312cd1-7d34-46ce-a7d3-0a98fd9b4cb8"  # notify: async events

# --- Opcodes -------------------------------------------------------------
OP_GET_ACCESS_SEED = 0x00
OP_UNLOCK          = 0x01
OP_GET_LIMITS      = 0x02
OP_READ_SHORT      = 0x10
OP_WRITE_SHORT     = 0x11

# --- Auth ----------------------------------------------------------------
_HANDSHAKE2 = base64.b64decode("ZMZFYlbyb1scoSc3pd1x+w==")  # 16 bytes

def auth_token(seed: bytes) -> bytes:
    return hashlib.sha256(_HANDSHAKE2 + seed[:16]).digest()[:16]

# --- Paths (subset; see puffco_path_map.json for the full map) -----------
P = {
    "name":   "/u/sys/name",
    "serial": "/p/sys/hw/ser",
    "fw":     "/p/sys/fw/gith",
    "mac":    "/p/sys/bt/mac",
    "soc":    "/p/bat/soc",
    "htemp":  "/p/app/htr/temp",
    "state":  "/p/app/stat/id",
    "dabs":   "/p/app/odom/0/nc",
}
OP_STATE = {0:"initMemory",1:"initVersion",2:"initBattery",3:"masterOff",4:"sleep",
            5:"idle",6:"tempSelect",7:"preheat",8:"active",9:"fade",10:"versionDisplay",
            11:"batteryDisplay",12:"factoryTest",13:"bonding"}


class Puffco:
    def __init__(self, client: BleakClient):
        self.client = client
        self.seq = 0
        self.maxpayload = 128
        self.pending = {}                       # seqId -> asyncio.Future

    def _next_seq(self) -> int:
        self.seq = (self.seq + 1) % 65535
        return self.seq

    def _on_notify(self, _char, data: bytearray):
        if len(data) < 3:
            return
        seq = struct.unpack_from("<H", data, 0)[0]
        err = data[2]
        fut = self.pending.pop(seq, None)
        if fut and not fut.done():
            if err:
                fut.set_exception(RuntimeError(f"LORAX error {err} (seq {seq})"))
            else:
                fut.set_result(bytes(data[3:]))

    async def start(self):
        await self.client.start_notify(REPLY, self._on_notify)
        try:
            await self.client.start_notify(EVENT, self._on_notify)
        except Exception:
            pass                                # event char optional

    async def _transact(self, opcode: int, payload: bytes = b"", timeout=5.0) -> bytes:
        seq = self._next_seq()
        frame = struct.pack("<HB", seq, opcode) + payload
        fut = asyncio.get_event_loop().create_future()
        self.pending[seq] = fut
        await self.client.write_gatt_char(COMMAND, frame, response=False)
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.pending.pop(seq, None)

    async def auth(self):
        limits = await self._transact(OP_GET_LIMITS)
        if len(limits) >= 2:
            self.maxpayload = struct.unpack_from("<H", limits, 0)[0]
        seed = await self._transact(OP_GET_ACCESS_SEED)
        await self._transact(OP_UNLOCK, auth_token(seed[:16]))

    # --- reads ---
    async def read(self, path: str) -> bytes:
        payload = struct.pack("<HH", 0, self.maxpayload) + path.encode("ascii")
        return await self._transact(OP_READ_SHORT, payload)

    async def read_float(self, path):  return struct.unpack("<f", (await self.read(path))[:4])[0]
    async def read_str(self, path):    return (await self.read(path)).split(b"\x00")[0].decode("latin1")
    async def read_u8(self, path):     return (await self.read(path))[0]
    async def read_mac(self, path):    return ":".join(f"{b:02x}" for b in (await self.read(path))[:6])

    # --- write (path ending /name uses bytePos=4, per LORAX) ---
    async def write(self, path: str, data: bytes):
        # bytePos: the reference impl uses 4 only for /name, but real app captures
        # show bp=4 on ALL writeShort frames (mc, hcs, led, time, name, ...), so
        # match the device: bytePos = 4.
        bp = 4
        payload = struct.pack("<HB", 0, bp) + path.encode("ascii") + b"\x00" + data
        await self._transact(OP_WRITE_SHORT, payload)


async def find(name_prefix=None, address=None):
    if address:
        return address
    devs = await BleakScanner.discover(timeout=8.0, return_adv=True)
    for dev, adv in devs.values():
        nm = (adv.local_name or dev.name or "")
        if SERVICE in [u.lower() for u in adv.service_uuids] or \
           (name_prefix and name_prefix.lower() in nm.lower()) or \
           (not name_prefix and any(k in nm.upper() for k in ("PUFFCO","PEAK","PROXY","PIVOT"))):
            print(f"found {nm or '?'}  [{dev.address}]")
            return dev.address
    raise SystemExit("No Puffco found. Wake the device / pass --name or --address.")


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name"); ap.add_argument("--address")
    a = ap.parse_args()
    addr = await find(a.name, a.address)
    async with BleakClient(addr) as client:
        dev = Puffco(client)
        await dev.start()
        await dev.auth()
        print("auth ok\n")
        c2f = lambda c: round(c * 1.8 + 32)
        print("Name        :", await dev.read_str(P["name"]))
        print("Serial      :", await dev.read_str(P["serial"]))
        print("Firmware    :", await dev.read_str(P["fw"]))
        print("BT MAC      :", await dev.read_mac(P["mac"]))
        print("Battery     :", round(await dev.read_float(P["soc"]), 1), "%")
        ht = await dev.read_float(P["htemp"])
        print("Heater temp :", round(ht, 1), f"C / {c2f(ht)} F")
        st = await dev.read_u8(P["state"])
        print("State       :", st, OP_STATE.get(st, "?"))
        print("Total dabs  :", int(await dev.read_float(P["dabs"])))
        # profiles
        print("\nHeat profiles:")
        for i in range(4):
            n  = await dev.read_str(f"/u/app/hc/{i}/name")
            t  = await dev.read_float(f"/u/app/hc/{i}/temp")
            tm = await dev.read_float(f"/u/app/hc/{i}/time")
            print(f"  {i+1}. {n:12s} {round(t,1)}C / {c2f(t)}F  {int(tm)}s")


if __name__ == "__main__":
    asyncio.run(main())
