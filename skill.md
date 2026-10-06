---
name: local-server-emulation-advanced
description: Advanced techniques for protocol-level reverse engineering, cryptographic license bypass, anti-tamper defeat, identity provider emulation, and hardware token emulation. Companion to local-server-emulation. Use when the target uses binary protocols, crypto-signed responses, anti-debug, hardware dongles, or cloud identity providers.
---

# Advanced Local Server Emulation & Protocol Bypass

Companion của `local-server-emulation`. Tầng này dành cho mục tiêu có:
- Protocol nhị phân (không phải HTTP/JSON)
- Response có signature cryptographic
- Anti-tamper / anti-debug / VM detection
- Cloud identity provider (OAuth2/OIDC/SAML)
- Hardware dongle hoặc smart card
- Update channel có signature chain
- DRM/KMS

---

## 1. Protocol Reverse Engineering nâng cao

### 1.1. Binary protocol families

| Protocol | Nhận dạng | Công cụ decode |
|----------|-----------|----------------|
| Protobuf | Field tag + wire type varint, không có magic | `protoc --decode_raw`, blackboxprotobuf |
| MessagePack | First byte 0x80-0x8f (fixmap), 0x90-0x9f (fixarray) | `msgpack` CLI, Python `msgpack` |
| Thrift | Version + type header, strict mode | `thrift --gen`, thrift-tools |
| Cap'n Proto | Segment framing, pointer arithmetic | `capnp decode` |
| FlatBuffers | Vtable offset đầu buffer | `flatc --raw-binary` |
| gRPC | HTTP/2 + `content-type: application/grpc` | `grpcurl`, `grpcui` |
| Custom TLV | Length-prefixed, thường 2/4 byte | Hex dump + manual parse |

### 1.2. gRPC server emulation

```python
# grpc_fake_license.py
# Yêu cầu: pip install grpcio grpcio-tools
# Bước 1: extract proto từ binary hoặc dùng reflection

import grpc
from concurrent import futures
import license_pb2
import license_pb2_grpc


class FakeLicenseServicer(license_pb2_grpc.LicenseServiceServicer):
    def CheckLicense(self, request, context):
        print(f"[>] CheckLicense machine_id={request.machine_id}")
        return license_pb2.LicenseResponse(
            status=license_pb2.LicenseResponse.VALID,
            expiry_unix=4102444800,  # 2099-12-31
            features=["pro", "export", "cloud"],
            signature=b"\x00" * 256
        )

    def Heartbeat(self, request, context):
        return license_pb2.HeartbeatResponse(status=True)


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    license_pb2_grpc.add_LicenseServiceServicer_to_server(
        FakeLicenseServicer(), server
    )

    # TLS nếu client yêu cầu
    with open('server.key', 'rb') as f:
        key = f.read()
    with open('server.crt', 'rb') as f:
        cert = f.read()
    creds = grpc.ssl_server_credentials([(key, cert)])
    server.add_secure_port('127.0.0.1:50051', creds)

    server.start()
    print("[*] Fake gRPC license server on 127.0.0.1:50051")
    server.wait_for_termination()


if __name__ == '__main__':
    serve()
```

**Extract proto với reflection:**
```bash
grpcurl -plaintext target:50051 list
grpcurl -plaintext target:50051 describe LicenseService
```

Nếu server không bật reflection: extract từ binary bằng IDA, tìm string `.proto` descriptors nhúng (protobuf descriptor pool).

### 1.3. Grammar inference tự động

```bash
# Netzob — infer state machine + grammar từ packet captures
pip install netzob
netzob -p capture.pcap --infer-grammar
```

**Tools:**
- **Netzob** — grammar + state machine từ traffic
- **Polyglot** — protocol grammar inference
- **Discoverer** — auto-RE binary protocol
- **Tupni** — input grammar inference từ binary

### 1.4. State machine extraction

Với protocol có session/state (multi-step auth):
1. Capture toàn bộ flow thành công
2. Label từng state (init, challenge, response, verify, done)
3. Vẽ state transition diagram
4. Fake server implement đúng state machine — không chỉ trả một response

```python
# stateful_fake_server.py — minh họa state machine
STATE = {}

class StatefulHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        session = self.headers.get('X-Session-Id', 'default')
        STATE.setdefault(session, {'step': 0})

        if self.path == '/auth/init':
            STATE[session]['nonce'] = os.urandom(16).hex()
            STATE[session]['step'] = 1
            self._send({'nonce': STATE[session]['nonce']})

        elif self.path == '/auth/challenge':
            # Verify client's HMAC — hoặc bỏ qua
            STATE[session]['step'] = 2
            self._send({'challenge_ok': True})

        elif self.path == '/auth/finalize':
            STATE[session]['step'] = 3
            self._send({'token': 'fake_jwt_here', 'status': 'valid'})
```

---

## 2. TLS-layer nâng cao

### 2.1. SSLKEYLOGFILE — decrypt không cần MITM

Nếu client là OpenSSL/BoringSSL/NSS, set env var trước khi chạy:

```bash
export SSLKEYLOGFILE=/tmp/keys.log
./target
# Sau đó Wireshark → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
```

Không cần cài CA cert, không cần proxy. Nhưng phải patch binary nếu nó tự clear env hoặc dùng library không support.

### 2.2. Hook OpenSSL/BoringSSL internals

Khi pinning chặn proxy, hook thẳng vào hàm encrypt/decrypt:

```javascript
// openssl_hook.js — Frida
// Hook SSL_write / SSL_read để dump plaintext

const ssl_write = Module.findExportByName(null, "SSL_write");
const ssl_read = Module.findExportByName(null, "SSL_read");

Interceptor.attach(ssl_write, {
    onEnter: function(args) {
        const buf = args[1];
        const len = args[2].toInt32();
        console.log(`[SSL_write ${len}] ` + hexdump(buf, {length: Math.min(len, 256)}));
    }
});

Interceptor.attach(ssl_read, {
    onLeave: function(retval) {
        const len = retval.toInt32();
        if (len > 0) {
            console.log(`[SSL_read ${len}] ` + hexdump(this.buf, {length: Math.min(len, 256)}));
        }
    }
});
```

### 2.3. QUIC / HTTP3 emulation

QUIC dùng UDP/443, TLS 1.3 nhúng trong. Proxy HTTP không bắt được.

**Công cụ:**
- **qvis** — QUIC visualization
- **quic-go** — Go QUIC server library
- **ngtcp2** — C QUIC implementation
- **aioquic** — Python QUIC

```python
# aioquic fake server skeleton
from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.h3.connection import H3Connection

# Cần reimplement H3 handler — tham khảo aioquic/examples/http3_server.py
```

QUIC thường gặp ở: Google services, Cloudflare, một số app mobile.

### 2.4. JA3/JA4 fingerprint matching

Server thật có thể reject nếu TLS ClientHello fingerprint lạ. Fake server phải có fingerprint khớp client gốc — hoặc patch client.

**Công cụ:**
- **ja3** — TLS fingerprint
- **cycle_tls** — TLS fingerprint spoofing
- **uTLS** — Go library để mimic browser/client TLS

### 2.5. mTLS — extract client cert

Server thật yêu cầu client cert. Client cert nhúng trong binary thường ở dạng:
- PEM string
- PKCS#12 blob (base64)
- Windows cert store reference

**Extract:**
```bash
# Tìm base64 blob
strings -n 100 target.exe | grep -E '^[A-Za-z0-9+/=]{200,}' > candidates.txt

# Decode và check magic
for line in $(cat candidates.txt); do
    echo "$line" | base64 -d 2>/dev/null | file - 
done
```

PKCS#12 thường bắt đầu `MII...` (base64 DER). Sau khi extract:
```bash
openssl pkcs12 -in client.p12 -nodes -out client.pem
# Cần password — thường hardcoded trong binary hoặc empty
```

---

## 3. Cryptographic attacks

### 3.1. RSA — weak key recovery

**Wiener's attack** (small d):
```python
# pip install owiener
import owiener
d = owiener.attack(e, n)
```

**Boneh-Durfee** (d < n^0.292):
```python
# pip install boneh_durfee
# Dùng sage — xem https://github.com/mimoo/RSA-and-LLL-attacks
```

**Common modulus attack** (same n, different e):
```python
from Crypto.Util.number import GCD, inverse
# Nếu có c1 = m^e1 mod n và c2 = m^e2 mod n
# Với gcd(e1, e2) = 1: m = c1^a * c2^b mod n
```

**Fermat factorization** (p, q gần nhau):
```python
from math import isqrt

def fermat(n):
    a = isqrt(n) + 1
    while True:
        b2 = a*a - n
        b = isqrt(b2)
        if b*b == b2:
            return a - b, a + b
        a += 1
```

**Shared primes** (nhiều modulus, cùng p):
```python
from math import gcd
for i in range(len(ns)):
    for j in range(i+1, len(ns)):
        p = gcd(ns[i], ns[j])
        if p > 1:
            print(f"Shared prime between {i}, {j}: {p}")
```

**ROCA** (CVE-2017-15361, Infineon):
```bash
# Công cụ: https://github.com/crocs-muni/roca
roca detect --key public.pem
```

### 3.2. ECDSA nonce recovery

Nếu hai signature dùng cùng nonce k:

```python
# r, s từ hai signature, z là hash của message
# k = (z1 - z2) * inverse(s1 - s2, n) mod n
# d = (s1 * k - z1) * inverse(r, n) mod n

from Crypto.Util.number import inverse

def recover_privkey(r, s1, s2, z1, z2, n):
    k = ((z1 - z2) * inverse(s1 - s2, n)) % n
    d = ((s1 * k - z1) * inverse(r, n)) % n
    return d
```

**Biased nonce (lattice attack):**
```bash
# Công cụ: https://github.com/bitlogik/lattice-attack
# Input: danh sách signature với nonce có MSB/LSB bias
```

Nếu license server dùng ECDSA ký response và bạn bắt được nhiều signature — check nonce reuse trước tiên.

### 3.3. Padding oracle trên RSA-PKCS1v1.5

Nếu license verify dùng RSA-PKCS1v1.5 và leak timing/error khác nhau cho padding sai vs signature sai — có thể forge signature.

**Bleichenbacher attack** — byte-by-byte oracle để decrypt hoặc forge.

**Công cụ:** `padbuster`, `pkcs1-padding-oracle` scripts.

### 3.4. Hash collision

Nếu license hash dùng MD5/SHA-1 — collision attack để tạo license giả với cùng hash.

```bash
# MD5 collision: https://github.com/cr-marcstevens/sha1collisiondetection
# SHA-1 collision: SHAttered (2017)
```

Hiếm gặp ở phần mềm mới, nhưng đồ cũ vẫn dính.

---

## 4. Anti-tamper bypass

### 4.1. Packer / protector nhận dạng

| Protector | Dấu hiệu | Cách xử lý |
|-----------|----------|------------|
| VMProtect | `.vmp0`, `.vmp1` sections | Devirtualize (khó) hoặc unpack via dump |
| Themida | `.themida`, `.winlice` | Unpack via OEP finder + dump |
| Enigma | Multiple sections, encrypted | Dump after unpack |
| ASPack | `.aspack`, `.adata` | Classic unpacker |
| UPX | `UPX0`, `UPX1` | `upx -d` |
| Denuvo | VM-based, anti-debug chained | Cực khó — thường bó tay |

**Unpack workflow:**
1. Chạy dưới debugger, break ở OEP
2. Dump process memory (`Scylla`, `PE-sieve`, `x64dbg dump`)
3. Fix IAT (`Scylla`, `ImpRec`)
4. Rebuild PE

### 4.2. Control flow flattening

Binary dùng dispatcher loop với state variable. Devirtualize:
- **Triton** — symbolic execution
- **Miasm** — IR + symbolic
- **D-810** (IDA plugin) — deobfuscation
- **GOOMBA** — control flow recovery

### 4.3. Anti-debug bypass

| Kỹ thuật | Bypass |
|----------|--------|
| `IsDebuggerPresent` | Patch return 0, hook |
| `CheckRemoteDebuggerPresent` | Patch return 0 |
| PEB.BeingDebugged | Patch PEB byte |
| Hardware breakpoints (Dr0-Dr7) | Clear via `SetThreadContext` |
| Timing checks (rdtsc, QPC) | Hook + return constant delta |
| TLS callbacks | Break ở TLS callback, patch before main |
| `NtQueryInformationProcess` | Hook, fake `ProcessDebugPort` |
| Exception-based (INT3, INT2D) | Hook `UnhandledExceptionFilter` |
| VM detection (CPUID, MAC, disk) | Hook CPUID, spoof MAC |

**Frida anti-anti-debug template:**
```javascript
// Hide from debugger
const pIsDebuggerPresent = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
Interceptor.replace(pIsDebuggerPresent, new NativeCallback(() => 0, 'int', []));

const pCheckRemote = Module.findExportByName("kernel32.dll", "CheckRemoteDebuggerPresent");
Interceptor.replace(pCheckRemote, new NativeCallback((h, p) => {
    p.writeU8(0);
    return 1;
}, 'int', ['pointer', 'pointer']));

// Clear PEB.BeingDebugged
const peb = Module.findExportByName("ntdll.dll", "NtCurrentPeb");
// hoặc: Memory.readU8(Module.getBaseAddress("ntdll.dll").add(offset))
```

### 4.4. Integrity checks

Binary tự hash sections và so với giá trị nhúng. Bypass:
- Patch hash comparison → luôn return true
- Patch stored hash → khớp với modified binary
- Hook hash function (CRC32, SHA, custom)

```javascript
// Hook CRC32 nếu dùng zlib
const crc32 = Module.findExportByName(null, "crc32");
Interceptor.attach(crc32, {
    onLeave: function(retval) {
        // Trả về giá trị gốc đã lưu
        retval.replace(ptr("0x12345678"));
    }
});
```

### 4.5. Authenticode / code signature

Nếu binary check signature của chính nó hoặc của DLL:
- **Sigthief** — copy signature từ binary đã ký sang binary modified
- **osslsigncode** — ký lại với cert giả (nếu không chain to trusted root thì vô dụng cho OS, nhưng app check signature có thể chấp nhận)
- Hook `WinVerifyTrust` → return 0

```javascript
// Hook WinVerifyTrust
const wvt = Module.findExportByName("wintrust.dll", "WinVerifyTrust");
Interceptor.replace(wvt, new NativeCallback(() => 0, 'int', ['pointer', 'pointer', 'pointer']));
```

---

## 5. Runtime instrumentation nâng cao

### 5.1. Frida Stalker — trace toàn bộ execution

```javascript
// Trace mọi instruction trong function license_check
const target = DebugSymbol.fromName("license_check").address;
Stalker.follow(Process.getCurrentThreadId(), {
    events: { call: true, ret: true, exec: true },
    onReceive: function(events) {
        // parse events
    },
    transform: function(iterator) {
        let instruction = iterator.next();
        do {
            if (instruction.mnemonic === 'call') {
                console.log(`[call] ${instruction.address} → ${instruction.operands[0]}`);
            }
            iterator.keep();
        } while ((instruction = iterator.next()) !== null);
    }
});
```

### 5.2. Frida CModule — hook inline bằng C

```javascript
const cm = new CModule(`
#include <gum/guminterceptor.h>

void on_enter(GumInvocationContext *ic) {
    // hook logic
}
`);

Interceptor.attach(target, {
    onEnter: cm.on_enter
});
```

### 5.3. Page guard hooks

Với hàm khó hook (inlined, hook detection), dùng page guard:

```c
// Set PAGE_GUARD trên page chứa code
// Khi instruction trong page execute → exception
// VEH handler dispatch tới hook logic
```

Công cụ: **MinHook**, **Detours**, **PolyHook2**.

### 5.4. WinDbg TTD — time travel debugging

```bash
# Record toàn bộ execution
tttracer.exe target.exe

# Sau đó:
windbg -z target01.run
# Time travel: !tt 0:100, g-, dx @$curprocess
```

Dùng khi cần trace dài, non-deterministic, hoặc multi-thread.

### 5.5. DynamoRIO / Intel PIN

Instrumentation framework, mạnh hơn Frida cho coverage/taint analysis:

```bash
# DynamoRIO
drrun -c drcov -- target.exe    # coverage
drrun -c drltrace -- target.exe # library call trace
```

---

## 6. Network-layer nâng cao

### 6.1. eBPF-based interception (Linux)

Không cần proxy, không cần CA cert — hook ở kernel:

```c
// tc-bpf hook cho traffic
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    // parse packet, rewrite response
    return TC_ACT_OK;
}
```

Công cụ: **Cilium**, **bcc**, **bpftrace**.

```bash
# bpftrace — trace connect() syscall
bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf("%s → %s\n", comm, args->uservaddr); }'
```

### 6.2. Network namespace isolation

```bash
# Tạo netns riêng cho target
ip netns add fakenet
ip netns exec fakenet ./target

# Trong netns đó, mọi traffic đều tới interface ảo
# Bind fake server vào interface đó
```

### 6.3. Transparent proxy

```bash
# iptables REDIRECT — không cần app config proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080

# TPROXY — giữ nguyên source IP
iptables -t mangle -A PREROUTING -p tcp --dport 443 -j TPROXY \
    --on-port 8080 --tproxy-mark 0x1/0x1
```

### 6.4. Custom TUN/TAP

Tạo network device ảo, capture toàn bộ traffic ở tầng IP:

```python
# Python với pytun
import pytun

tun = pytun.TunTapDevice(name='faketun', flags=pytun.IFF_TUN | pytun.IFF_NO_PI)
tun.addr = '10.0.0.1'
tun.netmask = '255.255.255.0'
tun.up()

while True:
    packet = tun.read(2048)
    # parse IP packet, craft response
    tun.write(response)
```

### 6.5. DNS spoofing

```bash
# dnsmasq — local DNS server
echo "address=/api.example.com/127.0.0.1" >> /etc/dnsmasq.conf
dnsmasq --no-daemon

# Hoặc dùng systemd-resolved drop-in
```

---

## 7. Cloud / Identity Provider emulation

### 7.1. OAuth2 / OIDC IdP emulation

Client thường:
1. Redirect user tới `https://idp.example.com/authorize`
2. IdP redirect về `https://app/callback?code=xxx`
3. Client exchange `code` → `token` tại `/token`
4. Client verify JWT bằng JWKS tại `/jwks.json`

**Fake IdP:**

```python
# fake_idp.py — FastAPI
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
import jwt
import time
import uuid

app = FastAPI()

# Tạo RSA keypair cho JWKS
from cryptography.hazmat.primitives.asymmetric import rsa
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export JWKS
from cryptography.hazmat.primitives import serialization
import base64

def b64url(n):
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

pub_numbers = public_key.public_numbers()

JWKS = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "fake-key-1",
        "n": b64url(pub_numbers.n),
        "e": b64url(pub_numbers.e),
    }]
}


@app.get("/.well-known/openid-configuration")
def discovery():
    return {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/authorize",
        "token_endpoint": "https://idp.example.com/token",
        "jwks_uri": "https://idp.example.com/jwks.json",
    }


@app.get("/jwks.json")
def jwks():
    return JWKS


@app.get("/authorize")
def authorize(request: Request):
    redirect_uri = request.query_params.get("redirect_uri")
    state = request.query_params.get("state", "")
    code = str(uuid.uuid4())
    return RedirectResponse(f"{redirect_uri}?code={code}&state={state}")


@app.post("/token")
async def token(request: Request):
    # Trả về JWT giả
    now = int(time.time())
    payload = {
        "iss": "https://idp.example.com",
        "sub": "fake-user",
        "aud": "target-app",
        "iat": now,
        "exp": now + 3600,
        "email": "user@example.com",
        "email_verified": True,
    }
    token = jwt.encode(payload, private_key, algorithm="RS256",
                       headers={"kid": "fake-key-1"})
    return {
        "access_token": token,
        "id_token": token,
        "refresh_token": "fake-refresh",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
```

**Vấn đề:** client pin public key của IdP thật → phải patch public key trong binary (xem mục 3 advanced gốc).

### 7.2. SAML IdP emulation

SAML dùng XML signature. Tương tự OIDC nhưng phức tạp hơn:
- Client fetch metadata từ `/metadata`
- IdP POST SAMLResponse về ACS URL
- SAMLResponse có XML signature

Công cụ: **pysaml2**, **python3-saml**. Có lỗ hổng SAML nổi tiếng:
- **XML Signature Wrapping (XSW)** — move signed element, inject forged
- **Comment injection** trong NameID
- **Signature stripping** nếu client không check

### 7.3. Fake S3 / GCS / Azure Blob

Client upload/download qua cloud storage:

```python
# fake_s3.py — dùng moto hoặc viết tay
# pip install moto[server]
# moto_server s3 -p 5000

# Hoặc endpoint giả trong FastAPI
@app.put("/{bucket}/{key:path}")
async def put_object(bucket: str, key: str, request: Request):
    body = await request.body()
    storage[f"{bucket}/{key}"] = body
    return {"ETag": hashlib.md5(body).hexdigest()}
```

Sau đó patch client endpoint từ `s3.amazonaws.com` → `127.0.0.1:5000` (hoặc hosts redirect + cert).

### 7.4. Firebase emulation

```bash
# Firebase emulator suite
firebase emulators:start --only auth,firestore,storage
```

Nếu client dùng Firebase REST API — dựng fake endpoint tương thích.

---

## 8. Hardware token emulation

### 8.1. Dongle emulation (HASP, Sentinel, CodeMeter)

Các bước:
1. **Capture USB traffic** — Wireshark + USBPcap (Windows), `usbmon` (Linux)
2. **Xác định protocol** — HASP dùng vendor-specific commands
3. **Emulate USB device** — dùng Facedancer (hardware) hoặc USB/IP (software)

**Công cụ:**
- **Facedancer** — USB device emulation via hardware (GreatFET, RPi)
- **usbip** — USB over IP, forward device đến VM
- **LUNA** — USB research board
- **HASP emulator** (cộng đồng) — nhiều bản cho HASP HL

**Quy trình HASP HL:**
```
Client → USB HASP dongle → response
Emulate: cài HASP driver + fake dongle DLL
```

Thường là: extract key material từ dongle (nếu có access), hoặc full protocol emulation (nếu chỉ cần response).

### 8.2. USB HID / CDC emulation

Với token giả dạng HID:

```python
# PyUSB + gadget kernel module (Linux)
# Dùng configfs để tạo USB gadget
```

Trên Linux:
```bash
# Tạo USB gadget qua configfs
mkdir /sys/kernel/config/usb_gadget/fakedongle
cd /sys/kernel/config/usb_gadget/fakedongle
echo 0x1234 > idVendor
echo 0x5678 > idProduct
# ... cấu hình endpoint, hàm xử lý
```

### 8.3. Smart card / PKCS#11 emulation

Nếu license yêu cầu smart card (PKCS#11 token):
1. **Extract key material** từ token thật (nếu có access)
2. **Emulate PKCS#11 module** — viết DLL export đúng hàm `C_*`
3. **Patch app** — trỏ đến PKCS#11 module giả

**SoftHSM** — software HSM, PKCS#11 compatible:
```bash
softhsm2-util --init-token --slot 0 --label fake
softhsm2-util --import key.pem --token fake --label license-key
```

Sau đó patch config app → dùng SoftHSM library.

---

## 9. Time & revocation

### 9.1. Time freezing

```bash
# libfaketime — LD_PRELOAD
export LD_PRELOAD=/usr/lib/faketime/libfaketime.so.1
export FAKETIME="2024-01-01 00:00:00"
./target
```

**Windows:** dùng **RunAsDate** hoặc hook `GetSystemTime`, `GetLocalTime`, `NtQuerySystemTime`.

```javascript
// Frida hook GetSystemTime
const pGetSystemTime = Module.findExportByName("kernel32.dll", "GetSystemTime");
Interceptor.attach(pGetSystemTime, {
    onEnter: function(args) {
        // ghi SYSTEMTIME giả vào args[0]
        const fake = Memory.alloc(16);
        // ... fill with fake time
        args[0].writeByteArray(fake.readByteArray(16));
    }
});
```

### 9.2. Bypass clock rollback detection

Nếu license lưu "last seen time" và phát hiện rollback:
- Patch check function
- Hook file/registry write → giữ giá trị cũ
- Freeze time từ đầu (không chỉ một thời điểm)

### 9.3. Fake OCSP / CRL responder

Nếu client check revocation:

```python
# OCSP responder đơn giản
@app.post("/ocsp")
async def ocsp(request: Request):
    # Parse OCSP request, trả về "good" status
    return Response(
        content=b"\x30\x03\x0a\x01\x00",  # OCSPResponse: good
        media_type="application/ocsp-response"
    )
```

Hoặc chặn URL OCSP → trả response "unknown" (một số client accept).

---

## 10. Update channel emulation

### 10.1. Sparkle (macOS)

Sparkle dùng appcast XML + EdDSA signature. Fake:
1. Dựng HTTP server phục vụ `appcast.xml`
2. Tạo EdDSA keypair, patch public key trong app
3. Sign appcast bằng private key

### 10.2. Omaha (Google updater)

Protocol protobuf qua HTTPS. Reverse proto, dựng fake server, patch endpoint.

### 10.3. Squirrel (Windows / Electron)

Check `RELEASES` file, tải `.nupkg`. Fake server phục vụ file giả.

### 10.4. TUF (The Update Framework)

Nếu app dùng TUF:
- Metadata có signature chain (root → targets → snapshot → timestamp)
- Cần toàn bộ private key để sign metadata giả
- Hoặc patch client bỏ verify (thường dễ hơn)

---

## 11. Detection-resistant deployment

### 11.1. Reflective DLL injection

Fake server logic chạy trong process target (không cần file .exe riêng):

```c
// Reflective loader — nạp DLL từ memory
// Công cụ: https://github.com/stephenfewer/ReflectiveDLLInjection
```

### 11.2. Memory-only execution

Không để lại file trên disk:
- PowerShell `IEX (New-Object Net.WebClient).DownloadString(...)`
- .NET `Assembly.Load(byte[])`
- Cobalt Strike-style Beacon

### 11.3. DLL proxying

Thay DLL hệ thống bằng proxy DLL:
1. Rename DLL gốc → `ws2_32_orig.dll`
2. Tạo DLL mới `ws2_32.dll` export đúng hàm, forward sang orig, hook các hàm cần
3. App load proxy → hook active

Công cụ: **DLLProxy**, **SharpDllProxy**, **Koppeling**.

### 11.4. Inline hooks

Patch 5 byte đầu của hàm (jmp to hook):

```c
// MinHook
MH_CreateHook(&target_function, &detour, &original);
MH_EnableHook(&target_function);
```

---

## 12. DRM/KMS

### 12.1. Widevine L3

Widevine L3 dùng software CDM. Có thể extract keys từ memory:
- **pywidevine** — L3 CDM emulation
- Extract từ Android emulator hoặc device
- Cần `device_client_id_blob` + `device_private_key`

Không phải local server emulation thuần, nhưng cùng pipeline: reverse protocol → fake CDM license server.

### 12.2. PlayReady

Phức tạp hơn Widevine. Cần extract từ Windows PlayReady runtime hoặc emulate full chain.

### 12.3. FairPlay (Apple)

Chỉ chạy trên Apple platform. Cần patch hoặc dùng CDM đã extract.

---

## 13. Checklist advanced

- [ ] Protocol family xác định (HTTP/gRPC/protobuf/custom binary)
- [ ] State machine extracted (nếu multi-step)
- [ ] TLS bypass: SSLKEYLOGFILE, hook, hoặc key extract
- [ ] Crypto: check weak key, nonce reuse, padding oracle TRƯỚC khi patch
- [ ] Anti-tamper: unpack, anti-debug bypass, integrity patch
- [ ] Runtime: Frida/DynamoRIO/PIN hooks ổn định
- [ ] Network: proxy/hosts/eBPF/netns phù hợp
- [ ] Identity provider: OIDC/SAML emulation nếu cần
- [ ] Hardware token: dongle emulation hoặc key extract
- [ ] Time: freeze + rollback bypass
- [ ] Update channel: fake manifest + signature chain
- [ ] Deployment: memory-only hoặc proxy DLL để tránh detect

---

## 14. Gotchas advanced

- **Nonce reuse không rõ ràng** — server có thể dùng k an toàn; check trước khi giả định có lỗ hổng
- **Hash function custom** — không phải SHA/CRC chuẩn, phải reverse trước khi hook
- **Kernel-mode anti-cheat** — Frida/Detours không đủ, cần driver-level hook hoặc hardware
- **Code virtualization** — VMProtect/Themida chặn symbolic execution thông thường
- **Hardware attestation** — TPM, Secure Enclave, Keychain — không emulate được nếu không có hardware
- **Server-side state** — nếu server track state per-license trên cloud thật, fake server phải giữ session state đồng bộ
- **Multi-device licensing** — server có thể check device fingerprint, cần spoof

---

## 15. Tham chiếu nhanh advanced

| Kỹ thuật | Công cụ chính |
|----------|---------------|
| Binary protocol RE | `protoc --decode_raw`, Netzob, Polyglot |
| gRPC emulation | grpcio, grpcurl, reflection |
| TLS bypass | SSLKEYLOGFILE, Frida hooks, uTLS |
| QUIC emulation | aioquic, quic-go, ngtcp2 |
| RSA attacks | owiener, Boneh-Durfee, RsaCtfTool |
| ECDSA nonce | lattice-attack, custom Python |
| Anti-debug bypass | Frida, x64dbg plugins, Scylla Hide |
| Unpacking | Scylla, PE-sieve, x64dbg |
| Devirtualization | Triton, Miasm, D-810 |
| Runtime instrumentation | Frida Stalker, DynamoRIO, PIN |
| eBPF interception | Cilium, bcc, bpftrace |
| OIDC/SAML IdP | FastAPI + PyJWT, pysaml2 |
| Hardware dongle | Facedancer, usbip, LUNA |
| Smart card | SoftHSM2, PKCS#11 |
| Time freeze | libfaketime, RunAsDate, Frida |
| Update channel | Sparkle, Omaha, Squirrel emulators |
| DLL proxy | DLLProxy, Koppeling |
| Widevine | pywidevine |
