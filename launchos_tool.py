#!/usr/bin/env python3
"""
LaunchOS patch + 本地注册机一体脚本。

用法：
  python3 launchos_tool.py patch   # patch App
  python3 launchos_tool.py serve   # 启动本地服务
  python3 launchos_tool.py all     # patch 后启动本地服务
"""

import argparse
import base64
import json
import os
import shutil
import socketserver
import struct
import subprocess
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WORK = ROOT / "launchos_keygen_work"
PRIVATE_KEY = WORK / "private.pem"
PUBLIC_KEY = WORK / "public.pem"

APP = Path("/Applications/LaunchOS.app")
BIN = APP / "Contents/MacOS/LaunchOS"
INFO = APP / "Contents/Info.plist"
APP_PUBLIC_KEY = APP / "Contents/Resources/public.pem"

HOST = "127.0.0.1"
PORT = 8765
SUCCESS_CODE = 1000

TBZ = bytes.fromhex("b4000036")
NOP = bytes.fromhex("1f2003d5")
REPLACEMENTS = (
    (b"https://api.remixdesign.app/", b"http://127.000.000.001:8765/"),
    (b"https://api.remixdesign.site/", b"http://127.000.000.001:8765//"),
)


def run(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.check_call(cmd)


def plist(key: str) -> str:
    return subprocess.check_output(
        ["/usr/libexec/PlistBuddy", "-c", f"Print :{key}", str(INFO)],
        text=True,
    ).strip()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def parse_va(line: str) -> int | None:
    head = line.strip().split(None, 1)[0]
    if len(head) == 16 and all(c in "0123456789abcdefABCDEF" for c in head):
        return int(head, 16)
    return None


def arm64_slice(data: bytes) -> int:
    if data[:4] == b"\xcf\xfa\xed\xfe":
        return 0
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise SystemExit("unsupported Mach-O format")

    for i in range(struct.unpack_from(">I", data, 4)[0]):
        cputype, _, off, _, _ = struct.unpack_from(">IIIII", data, 8 + i * 20)
        if cputype == 0x0100000C:
            return off
    raise SystemExit("arm64 slice not found")


def text_segment(data: bytes, slice_off: int) -> tuple[int, int, int, int]:
    if data[slice_off : slice_off + 4] != b"\xcf\xfa\xed\xfe":
        raise SystemExit("arm64 slice is not MH_MAGIC_64")

    off = slice_off + 32
    for _ in range(struct.unpack_from("<I", data, slice_off + 16)[0]):
        cmd, size = struct.unpack_from("<II", data, off)
        segname = data[off + 8 : off + 24].split(b"\0", 1)[0]
        if cmd == 0x19 and segname == b"__TEXT":
            return struct.unpack_from("<QQQQ", data, off + 24)
        off += size
    raise SystemExit("__TEXT segment not found")


def va_to_offset(data: bytes, va: int) -> int:
    slice_off = arm64_slice(data)
    vmaddr, vmsize, fileoff, filesize = text_segment(data, slice_off)
    if not vmaddr <= va < vmaddr + min(vmsize, filesize):
        raise SystemExit(f"VA out of __TEXT file range: {va:#x}")
    return slice_off + fileoff + (va - vmaddr)


def find_sigcheck_offset(data: bytes) -> int:
    """定位 network error: si 前的响应签名校验分支。"""
    lines = subprocess.check_output(
        ["otool", "-arch", "arm64", "-tV", str(BIN)],
        text=True,
        errors="replace",
    ).splitlines()

    for err_idx, line in enumerate(lines):
        if "network error: si" not in line:
            continue

        block = lines[max(0, err_idx - 120) : err_idx]
        if not any("stringCompareWithSmolCheck" in x for x in block):
            continue

        for x in block:
            if "\ttbz" in x or x.strip().endswith((" nop", "\tnop")):
                va = parse_va(x)
                if va is not None:
                    return va_to_offset(data, va)

    raise SystemExit("sigcheck branch not found")


def der_to_raw(der: bytes) -> bytes:
    if len(der) < 8 or der[0] != 0x30:
        raise ValueError("not an ECDSA DER sequence")

    pos = 2 + (der[1] & 0x7F if der[1] & 0x80 else 0)
    if der[pos] != 0x02:
        raise ValueError("bad r")
    r = der[pos + 2 : pos + 2 + der[pos + 1]]
    pos += 2 + der[pos + 1]

    if der[pos] != 0x02:
        raise ValueError("bad s")
    s = der[pos + 2 : pos + 2 + der[pos + 1]]
    return r.lstrip(b"\0").rjust(32, b"\0") + s.lstrip(b"\0").rjust(32, b"\0")


def sign_es256(message: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(message)
        path = f.name
    try:
        der = subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", str(PRIVATE_KEY), path])
        return der_to_raw(der)
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def make_token(req: dict) -> tuple[str, dict]:
    now = int(time.time())
    email = str(req.get("email") or "keygen@example.com")
    key = str(req.get("key") or req.get("license") or req.get("licenseKey") or "KEYGEN")
    fingerprint = str(req.get("fingerprint") or "")

    payload = {
        "product": "LaunchOS",
        "tokenVersion": 1,
        "fingerprint": fingerprint,
        "tier": "pro",
        "buildVersion": str(req.get("buildVersion") or ""),
        "trialStartedAt": 0,
        "licenseId": "KG-" + uuid.uuid5(uuid.NAMESPACE_DNS, email + "|" + key).hex[:16],
        "machineId": str(req.get("machineId") or fingerprint or uuid.uuid4()),
        "iss": "remixdesign.launchos",
        "aud": ["launchos-macos"],
        "iat": now,
        "exp": now + 10 * 365 * 24 * 3600,
    }
    header = {"alg": "ES256", "typ": "JWT"}
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    ).encode()
    return signing_input.decode() + "." + b64url(sign_es256(signing_input)), payload


class Handler(BaseHTTPRequestHandler):
    def read_json(self) -> dict:
        raw = self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}"
        try:
            return json.loads(raw.decode())
        except Exception:
            return {}

    def send_json(self, obj: dict, status: int = 200) -> None:
        body = json.dumps(obj, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("timestamp", str(int(time.time())))
        self.send_header("nonce", str(uuid.uuid4()).upper())
        self.send_header("signature", "patched")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        req = self.read_json()
        print(f"POST {self.path} body={json.dumps(req, ensure_ascii=False)}")

        if "deactivate" in self.path:
            self.send_json({"message": "", "code": SUCCESS_CODE, "data": {"ok": True}, "ok": True})
            return

        token, payload = make_token(req)
        print("RESP " + json.dumps({"code": SUCCESS_CODE, "token_payload": payload}, ensure_ascii=False))
        self.send_json({"message": "", "code": SUCCESS_CODE, "data": {"token": token}, "token": token})

    def do_GET(self) -> None:
        data = {"maxMachineCount": 999, "activatedMachines": []} if "machines" in self.path else {"ok": True}
        self.send_json({"message": "", "code": SUCCESS_CODE, "data": data, **data})

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


class Server(socketserver.TCPServer):
    allow_reuse_address = True


def patch_binary() -> None:
    data = bytearray(BIN.read_bytes())

    for old, new in REPLACEMENTS:
        if len(old) != len(new):
            raise SystemExit(f"replacement length mismatch: {old!r} -> {new!r}")
        print(f"{old.decode()} old_count={data.count(old)} patched_count={data.count(new)}")
        data = bytearray(bytes(data).replace(old, new))

    off = find_sigcheck_offset(data)
    cur = bytes(data[off : off + 4])
    print(f"sigcheck offset={off:#x} bytes={cur.hex()}")

    if cur == TBZ:
        data[off : off + 4] = NOP
        print(f"sigcheck patched -> {NOP.hex()}")
    elif cur == NOP:
        print("sigcheck already patched")
    else:
        raise SystemExit(f"unexpected bytes at {off:#x}: {cur.hex()}")

    BIN.write_bytes(data)


def patch_app() -> None:
    for path in (APP, BIN, PUBLIC_KEY):
        if not path.exists():
            raise SystemExit(f"missing: {path}")

    print(f"LaunchOS version: {plist('CFBundleShortVersionString')} ({plist('CFBundleVersion')})")
    patch_binary()
    shutil.copyfile(PUBLIC_KEY, APP_PUBLIC_KEY)
    print(f"public.pem replaced: {APP_PUBLIC_KEY}")
    run(["xattr", "-cr", str(APP)])
    run(["codesign", "--force", "--deep", "--sign", "-", str(APP)])
    print("patch done")


def serve() -> None:
    if not PRIVATE_KEY.exists():
        raise SystemExit(f"missing: {PRIVATE_KEY}")

    with Server((HOST, PORT), Handler) as httpd:
        print(f"LaunchOS keygen server listening on http://{HOST}:{PORT}")
        httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="LaunchOS patch + keygen tool")
    parser.add_argument("command", choices=["patch", "serve", "all"])
    args = parser.parse_args()

    if args.command in ("patch", "all"):
        patch_app()
    if args.command in ("serve", "all"):
        serve()


if __name__ == "__main__":
    main()
