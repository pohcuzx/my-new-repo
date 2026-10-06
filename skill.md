---
name: local-server-emulation
description: Reverse engineering technique for building fake localhost servers to emulate real API/license servers. Covers loopback servers, API emulation, interception proxies, hosts redirection, and license server emulation. Use when analyzing software that depends on remote server responses for activation, licensing, or feature gating.
---

# Local Server Emulation & API Interception

Kỹ thuật reverse engineering dựng server giả trên localhost để mô phỏng API/license server thật — phục vụ phân tích phần mềm, nghiên cứu protocol, và kiểm thử cơ chế activation.

## Khi nào dùng

Phần mềm mục tiêu:
- Gửi request đến server từ xa để kiểm tra license/activation
- Gọi API để lấy cấu hình, update, hoặc feature flag
- Xác thực login qua endpoint HTTP/HTTPS
- Kiểm tra subscription/DRM theo chu kỳ
- Không hoạt động offline vì phụ thuộc server response

**Mục tiêu:** cắt phụ thuộc server thật bằng server giả trên máy, trả về response phần mềm chấp nhận.

---

## 1. Năm kỹ thuật cốt lõi

### 1.1. Localhost / Loopback Server

**Bản chất:** HTTP/HTTPS server bind vào `127.0.0.1` hoặc `localhost`.

**Đặc điểm:**
- Chỉ accessible từ chính máy — không lộ ra mạng ngoài
- Bind port bất kỳ: `80`, `443`, `8080`, `8443`, hoặc port phần mềm hardcode
- Dùng khi phần mềm đã được patch trỏ về localhost

**Tên gọi khác:** local server, local API server, loopback service.

---

### 1.2. Server Emulation / API Emulation

**Bản chất:** Phân tích server thật → viết server giả mô phỏng response.

**Quy trình:**
1. Bắt traffic giữa phần mềm và server thật (Wireshark, mitmproxy, Fiddler)
2. Xác định endpoint, method, headers, body format
3. Xác định response schema: status code, JSON/XML structure, token format
4. Viết server giả trả về đúng schema đó
5. Redirect phần mềm về server giả

**Dạng phổ biến:**
- REST API emulation (JSON)
- SOAP/XML emulation
- gRPC emulation (cần protobuf schema)
- WebSocket emulation (real-time check-in)

---

### 1.3. Local Proxy / Interception Proxy

**Bản chất:** Chương trình đứng giữa phần mềm và server thật, chặn và sửa request/response.

**Công cụ:** mitmproxy, Fiddler, Charles Proxy, Burp Suite.

**Cơ chế:**
- Phần mềm → proxy (localhost:8080) → server thật
- Proxy decrypt HTTPS (cài CA cert vào trust store)
- Sửa response trên đường về

**Khi nào dùng proxy thay fake server:**
- Chỉ cần sửa vài field trong response
- Không muốn viết lại toàn bộ server
- Cần giữ logic server thật cho các phần khác

---

### 1.4. Hosts Redirection / DNS Redirection

**Bản chất:** Chuyển domain phần mềm về `127.0.0.1`.

**Cách làm:**
- Sửa `C:\Windows\System32\drivers\etc\hosts` (Windows) hoặc `/etc/hosts` (Linux/macOS)
- Thêm: `127.0.0.1    api.example.com`

**Vấn đề:**
- HTTPS cert mismatch — server giả cần cert hợp lệ cho domain
- DNS-over-HTTPS hoặc hardcoded IP → hosts vô dụng

**Giải pháp cert:**
- Self-signed cert cho domain, cài vào trust store
- Hoặc patch binary bỏ qua cert check

---

### 1.5. License Server Emulation

**Bản chất:** Fake licensing server trả về `license valid`.

**Đặc thù:**
- Protocol riêng, không chỉ HTTP
- RSA/ECDSA signature — server giả phải ký response bằng đúng key, hoặc patch phần mềm bỏ verify
- Heartbeat/check-in định kỳ → server giả duy trì session

**Các bước:**
1. Reverse engineer client → tìm license check function
2. Xác định request format (JSON với machine ID, product key)
3. Xác định response format (`status`, `expiry`, `signature`)
4. Nếu có signature: extract public key từ binary, tạo keypair giả, patch public key, ký response
5. Dựng server, redirect client về đó

---

## 2. Pipeline tổng quát

```
Phần mềm
   │
   ├─► API/license endpoint (domain thật)
   │
   ▼
[Bắt traffic: mitmproxy / Wireshark]
   │
   ▼
[Phân tích protocol/response schema]
   │
   ▼
[Redirect về localhost: hosts file / patch binary / proxy]
   │
   ▼
[Local server giả lập response]
   │
   ▼
Phần mềm hoạt động như đã kích hoạt
```

---

## 3. Công cụ theo giai đoạn

| Giai đoạn | Công cụ |
|-----------|---------|
| Bắt traffic | Wireshark, tcpdump, mitmproxy, Fiddler |
| Phân tích HTTPS | mitmproxy + CA cert, Fiddler, Burp |
| Reverse binary | IDA Pro, Ghidra, x64dbg, Binary Ninja |
| Patch binary | x64dbg, HxD, LIEF, Python + pefile |
| Dựng server giả | Python (http.server, Flask, FastAPI), Node.js, Go |
| Redirect | hosts file, iptables, patch binary |
| Cert giả | openssl, mkcert |

---

## 4. Code mẫu

### 4.1. Fake API Server (Python, HTTPS)

```python
# fake_api_server.py
# Chạy: python fake_api_server.py
# Yêu cầu: server.crt + server.key (xem mục 4.2)

import json
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler


class FakeLicenseHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        print(f"[>] {self.path}")
        print(f"    {body.decode(errors='replace')}")

        if self.path == '/api/v1/license/check':
            response = {
                "status": "valid",
                "expiry": "2099-12-31T23:59:59Z",
                "features": ["pro", "export", "cloud"],
                "signature": "FAKE_SIG_PLACEHOLDER"
            }
        elif self.path == '/api/v1/heartbeat':
            response = {"status": "ok"}
        else:
            response = {"error": "unknown endpoint"}

        data = json.dumps(response).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"fake license server running")

    def log_message(self, fmt, *args):
        print(f"[server] {fmt % args}")


if __name__ == '__main__':
    host, port = '127.0.0.1', 8443
    httpd = HTTPServer((host, port), FakeLicenseHandler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile='server.crt', keyfile='server.key')
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"[*] Fake license server on https://{host}:{port}")
    httpd.serve_forever()
```

### 4.2. Tạo cert self-signed

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout server.key -out server.crt -days 365 \
  -subj "/CN=api.example.com" \
  -addext "subjectAltName=DNS:api.example.com"
```

### 4.3. mitmproxy Addon — sửa response

```python
# license_patch.py
# Chạy: mitmproxy -s license_patch.py

from mitmproxy import http
import json

TARGET_HOST = "api.example.com"
TARGET_PATH = "/api/v1/license/check"


def response(flow: http.HTTPFlow):
    if flow.request.host != TARGET_HOST:
        return
    if flow.request.path != TARGET_PATH:
        return

    try:
        data = json.loads(flow.response.content)
    except Exception:
        return

    data["status"] = "valid"
    data["expiry"] = "2099-12-31T23:59:59Z"
    data["features"] = ["pro", "export", "cloud"]

    flow.response.content = json.dumps(data).encode()
    flow.response.headers["Content-Type"] = "application/json"
    print(f"[+] patched response for {flow.request.path}")
```

### 4.4. Hosts entry

**Windows:** `C:\Windows\System32\drivers\etc\hosts`
**Linux/macOS:** `/etc/hosts`

```
127.0.0.1    api.example.com
127.0.0.1    license.example.com
```

### 4.5. Frida — bypass SSL pinning

```javascript
// ssl_bypass.js
// Chạy: frida -l ssl_bypass.js -f target.exe

Interceptor.attach(
    Module.findExportByName("libssl.so", "SSL_get_verify_result"),
    {
        onLeave: function(retval) {
            retval.replace(0); // X509_V_OK
        }
    }
);
```

### 4.6. Ký response bằng keypair giả

```python
# sign_response.py

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import base64

with open('fake_private.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)

payload = b'{"status":"valid","expiry":"2099-12-31"}'
signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
sig_b64 = base64.b64encode(signature).decode()
print(sig_b64)
```

```bash
# Tạo keypair giả
openssl genrsa -out fake_private.pem 2048
openssl rsa -in fake_private.pem -pubout -out fake_public.pem
```

---

## 5. Xử lý certificate pinning

Nếu phần mềm pin cert (không dùng trust store hệ thống), hosts + cert giả sẽ fail.

**Cách xử lý:**
1. **Patch binary** — tìm hàm verify cert, NOP hoặc return true
2. **Frida hook** — hook SSL_verify_result, X509_verify_cert, hoặc hàm custom
3. **Extract pinned cert** — nếu pin là public key, dùng đúng key đó ký cert giả

---

## 6. Xử lý license signature

Nếu response có signature verify bằng public key nhúng trong binary:

**Bước 1:** Extract public key từ binary (IDA/Ghidra, tìm PEM header hoặc key blob)

**Bước 2:** Tạo keypair giả:
```bash
openssl genrsa -out fake_private.pem 2048
openssl rsa -in fake_private.pem -pubout -out fake_public.pem
```

**Bước 3:** Patch binary — thay public key thật bằng public key giả

**Bước 4:** Server giả ký response bằng `fake_private.pem` (xem 4.6)

---

## 7. Checklist trước khi ship

- [ ] Bắt được traffic thật → biết endpoint, method, headers, body
- [ ] Xác định response schema → server giả trả đúng format
- [ ] Redirect phần mềm về localhost (hosts / patch / proxy)
- [ ] Cert hợp lệ nếu HTTPS (self-signed + trust store, hoặc patch pinning)
- [ ] Nếu có signature: keypair giả + patch public key trong binary
- [ ] Server giả chạy ổn định, log request để debug
- [ ] Phần mềm hoạt động đúng như mong đợi sau khi redirect

---

## 8. Gotchas

- **Hardcoded IP** — phần mềm hardcode IP server → hosts vô dụng, phải patch binary
- **DNS-over-HTTPS** — bypass hosts file bằng DoH → patch hoặc chặn DoH endpoint
- **Certificate pinning** — trust store không đủ, phải patch verify function
- **Mutual TLS** — server thật yêu cầu client cert → server giả chấp nhận cert bất kỳ hoặc extract client cert từ binary
- **Heartbeat/check-in** — server giả phải duy trì session, không chỉ trả một lần
- **Anti-debug** — phần mềm detect debugger/proxy → bypass trước
- **Encrypted request body** — body mã hóa bằng key nhúng binary → reverse hàm encrypt/decrypt

---

## 9. Tham chiếu nhanh

| Khái niệm | Tên kỹ thuật | Công cụ chính |
|-----------|--------------|---------------|
| Server giả trên localhost | Local server / loopback service | Python, Node, Go |
| Mô phỏng API thật | API emulation | Flask, FastAPI, mitmproxy |
| Chặn & sửa request/response | Interception proxy | mitmproxy, Fiddler, Burp |
| Chuyển domain về localhost | Hosts/DNS redirection | hosts file, iptables |
| Giả lập license server | License server emulation | Python + crypto libs |
| Bỏ cert pinning | SSL pinning bypass | Frida, x64dbg, patch |