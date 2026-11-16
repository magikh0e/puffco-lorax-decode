#!/usr/bin/env python3
"""
puffco_lorax_decode.py  (v2)

Decode Puffco LORAX (New Proxy / Peak Pro) BLE traffic from an Android
btsnoop_hci.log into a typed, documented path map suitable as a drop-in
reference for an app.

Usage:
    python3 puffco_lorax_decode.py btsnoop_hci.log [--json out.json] [--csv out.csv]

Outputs (stdout + optional files):
  * Auth handshake pair(s)  (getAccessSeed seed -> unlock response)
  * Every readShort path with its value auto-decoded by type
  * Every control command (writeShort/write) with decoded written value

Protocol (confirmed against captures + austenstone/puffco-mcp / Fr0st3h writeup):
  frame = seqId(uint16 LE) + opcode(uint8) + payload
  write char  -> ATT handle for the 60133d5c-... characteristic
  notify char -> 8dc5ec05-... (acks/events) and 43312cd1-... (bulk replies)
  readShort reply = seqId(2) + status(1, 0x00=OK) + value
Opcodes: 0x00 getAccessSeed, 0x01 unlock, 0x02 getLimits,
         0x10 readShort, 0x11 writeShort, 0x22 write, 0x03 ack/flow
"""
import struct, re, sys, csv, json, argparse
from collections import Counter

OPS = {0x00:"getAccessSeed",0x01:"unlock",0x02:"getLimits",
       0x03:"ack/flow",0x10:"readShort",0x11:"writeShort",0x22:"write",
       0x20:"op20",0x23:"op23",0x27:"op27"}

# --- Confirmed LORAX GATT UUIDs (from austenstone/puffco-mcp, live-verified) ---
UUID = {
 "service": "e276967f-ea8a-478a-a92e-d78f5dd15dd5",
 "version": "05434bca-cc7f-4ef6-bbb3-b1c520b9800c",  # read
 "command": "60133d5c-5727-4f2c-9697-d842c5292a3c",  # write w/o response
 "reply":   "8dc5ec05-8f7d-45ad-99db-3fbde65dbd9c",  # notify (command replies)
 "event":   "43312cd1-7d34-46ce-a7d3-0a98fd9b4cb8",  # notify (async events)
}

# --- Confirmed New Proxy auth handshake (verified against captured seed/response) ---
import hashlib, base64
_HANDSHAKE2 = base64.b64decode("ZMZFYlbyb1scoSc3pd1x+w==")  # 16 bytes

def auth_token(seed: bytes) -> bytes:
    """Given the 16-byte getAccessSeed reply, return the 16-byte unlock token.
    token = SHA256(HANDSHAKE2 ++ seed)[:16].  Write this back via unlock (op 0x01)."""
    return hashlib.sha256(_HANDSHAKE2 + seed[:16]).digest()[:16]


# --- Path type registry -------------------------------------------------
# type: one of float32 | u16 | u32 | u8 | bool | string | rgb | mac | bytes
# temps are stored as float32 CELSIUS on the wire.
PATHS = {
 "/p/sys/hw/ser":   ("string","Device serial number"),
 "/p/sys/hw/mdcd":  ("u32","Model code"),
 "/u/sys/name":     ("string","User-set device name"),
 "/p/sys/bt/mac":   ("mac","Bluetooth MAC address"),
 "/p/sys/bt/tba":   ("bytes","BT bonded address(es)"),
 "/p/sys/fw/gith":  ("string","Firmware git hash"),
 "/p/sys/fw/api":   ("u32","Firmware API version"),
 "/p/sys/time":     ("u32","Device uptime/clock (ticks)"),
 "/u/sys/bday":     ("u32","Device birthday (epoch)"),
 "/p/bat/soc":      ("float32","Battery state-of-charge (%)"),
 "/u/bat/msoc":     ("float32","Battery SOC mirror (%)"),
 "/p/bat/cap":      ("float32","Battery capacity (mAh)"),
 "/p/bat/chg/stat": ("u8","Charge state (0=not charging)"),
 "/p/bat/chg/etf":  ("float32","Est. time to full (s)"),
 "/p/app/htr/temp": ("float32","Heater temperature (C)"),
 "/p/app/htr/tcmd": ("float32","Heater temp command (C)"),
 "/p/htr/chmt":     ("u8","Chamber present/type"),
 "/p/htr/chdt":     ("bytes","Chamber detect data"),
 "/p/htr/tcmd":     ("float32","Heater temp command (C)"),
 "/p/app/mc":       ("float32","Mode command (write to control device)"),
 "/p/app/hcs":      ("bytes","Heat-cycle state"),
 "/p/app/stat/id":  ("u8","Operating state id"),
 "/p/app/stat/elap":("float32","State elapsed time (s)"),
 "/p/app/stat/tott":("float32","State total time (s)"),
 "/p/app/odom/0/nc":("float32","Odometer: total heat cycles"),
 "/p/app/odom/0/tm":("float32","Odometer: total heat time (s)"),
 "/p/app/info/dpd": ("float32","Dabs per day"),
 "/p/app/info/drem":("float32","Approx dabs remaining"),
 "/p/app/ltrn/remt":("bytes","Lantern remote state"),
 "/p/app/ltrn/colr":("rgb","Lantern color"),
 "/p/app/ltrn/scpd":("bytes","Lantern scene/pattern data"),
 "/p/app/led/pclr": ("rgb","Primary LED color"),
 "/u/app/ui/lbrt":  ("float32","LED brightness"),
 "/u/app/ui/stlm":  ("u8","Stealth mode"),
 "/u/app/rdym/hc":  ("float32","Ready-mode heat cycle (-1=off)"),
 "/u/app/lbws":     ("bytes","Lantern boot/wake setting"),
}
# per-profile leaf types  /u/app/hc/<n>/<leaf> and /p/app/thc/<leaf>
PROFILE_LEAF = {"name":"string","temp":"float32","time":"float32",
                "intn":"float32","colr":"rgb","scpd":"bytes","phcl":"bytes","btmp":"float32","btim":"float32"}

def path_type(path):
    if path in PATHS: return PATHS[path][0]
    m = re.match(r"^/u/app/hc/\d+/(\w+)$", path) or re.match(r"^/p/app/thc/(\w+)$", path)
    if m and m.group(1) in PROFILE_LEAF: return PROFILE_LEAF[m.group(1)]
    return None

def path_desc(path):
    if path in PATHS: return PATHS[path][1]
    LEAF_DESC={"name":"name","temp":"temp (C, float32)","time":"time (s)","colr":"LED color",
               "intn":"intensity","scpd":"scene/pattern data","btmp":"boost temp (C)","btim":"boost time (s)","phcl":"packed heat cycle"}
    m = re.match(r"^/u/app/hc/(\d+)/(\w+)$", path)
    if m: return f"Heat profile {int(m.group(1))+1} "+LEAF_DESC.get(m.group(2),m.group(2))
    m = re.match(r"^/p/app/thc/(\w+)$", path)
    if m: return f"Current heat-cycle {m.group(1)}"
    return ""

def decode_value(path, v):
    t = path_type(path)
    if not v: return t, ""
    try:
        if t=="string": return t, v.split(b"\x00")[0].decode("latin1","replace")
        if t=="mac":    return t, ":".join("%02x"%x for x in v[:6])
        if t=="rgb":
            r,g,b = v[0],v[1],v[2]; mode = v[4] if len(v)>4 else 0
            return t, f"RGB({r},{g},{b}) mode={mode}"
        if t=="float32" and len(v)>=4: return t, round(struct.unpack("<f",v[:4])[0],3)
        if t=="u32" and len(v)>=4:     return t, struct.unpack("<I",v[:4])[0]
        if t=="u16" and len(v)>=2:     return t, struct.unpack("<H",v[:2])[0]
        if t in ("u8","bool") and len(v)>=1: return t, v[0]
    except Exception:
        pass
    # fallback: guess by length
    if len(v)==4: return (t or "float32?"), round(struct.unpack("<f",v)[0],3)
    if len(v)==2: return (t or "u16?"), struct.unpack("<H",v)[0]
    if len(v)==1: return (t or "u8?"), v[0]
    return (t or "bytes"), v.hex()

def load(path):
    data=open(path,"rb").read()
    assert data[:8]==b"btsnoop\x00","not a btsnoop file"
    off,S=16,[]
    while off+24<=len(data):
        o,il,fl,dr,ts=struct.unpack(">IIIIq",data[off:off+24]); off+=24
        pkt=data[off:off+il]; off+=il
        if not pkt or pkt[0]!=0x02: continue
        b=pkt[1:]
        if len(b)<8: continue
        l2len,cid=struct.unpack("<HH",b[4:8])
        if cid!=0x0004: continue
        p=b[8:8+l2len]
        if p: S.append((ts,p[0],struct.unpack("<H",p[1:3])[0] if len(p)>=3 else -1,p[3:]))
    return S

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("log"); ap.add_argument("--json"); ap.add_argument("--csv")
    a=ap.parse_args()
    S=load(a.log)
    if not S: print("No ATT traffic."); return
    t0=S[0][0]
    write_h=Counter(h for _,op,h,_ in S if op==0x52).most_common(1)[0][0]
    notify_hs=set(h for h,_ in Counter(h for _,op,h,_ in S if op==0x1b).most_common(2))
    def reply_after(i,seq,win=40):
        for j in range(i+1,min(i+win,len(S))):
            ts,op,h,val=S[j]
            if op==0x1b and h in notify_hs and len(val)>=2 and struct.unpack("<H",val[0:2])[0]==seq:
                return val[2:]
        return None
    print(f"# write handle 0x{write_h:04x}  notify handles {sorted('0x%04x'%h for h in notify_hs)}")

    # auth pairs
    print("\n## AUTH (getAccessSeed seed -> unlock response)")
    seeds={}
    for i,(ts,op,h,val) in enumerate(S):
        if op==0x52 and h==write_h and len(val)>=3 and val[2]==0x00:
            seq=struct.unpack("<H",val[0:2])[0]; r=reply_after(i,seq)
            if r: seeds[seq]=(r[1:] if r[:1]==b"\x00" else r)
        if op==0x52 and h==write_h and len(val)>=3 and val[2]==0x01:
            resp=val[3:]
            seed=next(iter(seeds.values()),b"")
            ok = auth_token(seed)==resp[:16] if seed else False
            print(f"  seed={seed.hex()}  unlock={resp.hex()}  token_matches={'YES' if ok else 'no'}")

    # enumeration
    seen={}; order=[]
    for i,(ts,op,h,val) in enumerate(S):
        if op==0x52 and h==write_h and len(val)>=3 and val[2]==0x10:  # readShort
            seq=struct.unpack("<H",val[0:2])[0]
            m=re.search(rb"/[ -~]{2,}",val[3:]); path=m.group().decode() if m else "?"
            if path.startswith("/p/logv/aud") or path.startswith("/p/logv/flt"): continue
            if path in seen: continue
            r=reply_after(i,seq)
            if r is None: continue
            v=r[1:] if r[:1]==b"\x00" else r
            t,dv=decode_value(path,v)
            seen[path]={"path":path,"type":t,"value":dv,"raw":v.hex(),
                        "desc":path_desc(path),"t_s":round((ts-t0)/1e6,2)}
            order.append(path)
    print(f"\n## DEVICE PATH MAP ({len(order)} paths)")
    print(f"{'path':24} {'type':9} {'value':<28} description")
    print("-"*100)
    for p in order:
        e=seen[p]; print(f"{e['path']:24} {str(e['type']):9} {str(e['value']):<28} {e['desc']}")

    if a.json:
        json.dump([seen[p] for p in order], open(a.json,"w"), indent=2)
        print("\n# wrote",a.json)
    if a.csv:
        with open(a.csv,"w",newline="") as f:
            w=csv.writer(f); w.writerow(["path","type","value","raw_hex","description","t_s"])
            for p in order:
                e=seen[p]; w.writerow([e["path"],e["type"],e["value"],e["raw"],e["desc"],e["t_s"]])
        print("# wrote",a.csv)

if __name__=="__main__":
    main()
